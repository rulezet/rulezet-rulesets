rule TTP_XOR_WriteProcessMemory_3242 {
  strings:
    $key_3242 = { 65 30 [2] 57 12 [2] 51 27 [2] 7f 27 [2] 40 3b }

  condition:
    any of them
}