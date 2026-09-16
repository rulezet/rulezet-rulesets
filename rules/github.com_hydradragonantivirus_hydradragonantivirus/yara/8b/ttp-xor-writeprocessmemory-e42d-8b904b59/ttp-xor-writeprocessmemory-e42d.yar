rule TTP_XOR_WriteProcessMemory_e42d {
  strings:
    $key_e42d = { b3 5f [2] 81 7d [2] 87 48 [2] a9 48 [2] 96 54 }

  condition:
    any of them
}