rule TTP_XOR_WriteProcessMemory_e44c {
  strings:
    $key_e44c = { b3 3e [2] 81 1c [2] 87 29 [2] a9 29 [2] 96 35 }

  condition:
    any of them
}