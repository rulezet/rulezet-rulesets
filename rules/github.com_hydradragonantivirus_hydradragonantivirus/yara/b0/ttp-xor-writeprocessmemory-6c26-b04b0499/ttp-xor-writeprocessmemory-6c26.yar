rule TTP_XOR_WriteProcessMemory_6c26 {
  strings:
    $key_6c26 = { 3b 54 [2] 09 76 [2] 0f 43 [2] 21 43 [2] 1e 5f }

  condition:
    any of them
}