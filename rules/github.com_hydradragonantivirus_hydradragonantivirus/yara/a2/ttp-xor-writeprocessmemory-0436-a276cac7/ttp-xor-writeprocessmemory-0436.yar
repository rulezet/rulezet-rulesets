rule TTP_XOR_WriteProcessMemory_0436 {
  strings:
    $key_0436 = { 53 44 [2] 61 66 [2] 67 53 [2] 49 53 [2] 76 4f }

  condition:
    any of them
}