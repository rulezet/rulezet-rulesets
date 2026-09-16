rule TTP_XOR_WriteProcessMemory_e351 {
  strings:
    $key_e351 = { b4 23 [2] 86 01 [2] 80 34 [2] ae 34 [2] 91 28 }

  condition:
    any of them
}