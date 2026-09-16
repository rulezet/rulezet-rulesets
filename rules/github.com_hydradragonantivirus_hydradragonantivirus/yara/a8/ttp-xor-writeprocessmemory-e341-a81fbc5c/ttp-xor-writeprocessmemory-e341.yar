rule TTP_XOR_WriteProcessMemory_e341 {
  strings:
    $key_e341 = { b4 33 [2] 86 11 [2] 80 24 [2] ae 24 [2] 91 38 }

  condition:
    any of them
}