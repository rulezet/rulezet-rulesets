rule TTP_XOR_WriteProcessMemory_6c13 {
  strings:
    $key_6c13 = { 3b 61 [2] 09 43 [2] 0f 76 [2] 21 76 [2] 1e 6a }

  condition:
    any of them
}