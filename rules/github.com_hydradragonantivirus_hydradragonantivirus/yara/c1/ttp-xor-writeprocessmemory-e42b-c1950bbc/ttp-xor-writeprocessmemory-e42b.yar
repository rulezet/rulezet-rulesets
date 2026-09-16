rule TTP_XOR_WriteProcessMemory_e42b {
  strings:
    $key_e42b = { b3 59 [2] 81 7b [2] 87 4e [2] a9 4e [2] 96 52 }

  condition:
    any of them
}