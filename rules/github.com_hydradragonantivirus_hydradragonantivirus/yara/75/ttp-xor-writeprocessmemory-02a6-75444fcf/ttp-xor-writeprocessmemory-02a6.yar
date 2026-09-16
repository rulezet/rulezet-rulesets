rule TTP_XOR_WriteProcessMemory_02a6 {
  strings:
    $key_02a6 = { 55 d4 [2] 67 f6 [2] 61 c3 [2] 4f c3 [2] 70 df }

  condition:
    any of them
}