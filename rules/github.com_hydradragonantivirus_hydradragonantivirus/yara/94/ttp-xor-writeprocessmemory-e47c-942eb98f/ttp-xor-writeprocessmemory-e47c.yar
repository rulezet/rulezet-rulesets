rule TTP_XOR_WriteProcessMemory_e47c {
  strings:
    $key_e47c = { b3 0e [2] 81 2c [2] 87 19 [2] a9 19 [2] 96 05 }

  condition:
    any of them
}