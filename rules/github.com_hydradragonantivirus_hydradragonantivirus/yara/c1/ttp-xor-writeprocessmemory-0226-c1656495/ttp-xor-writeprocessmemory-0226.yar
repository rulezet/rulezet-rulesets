rule TTP_XOR_WriteProcessMemory_0226 {
  strings:
    $key_0226 = { 55 54 [2] 67 76 [2] 61 43 [2] 4f 43 [2] 70 5f }

  condition:
    any of them
}