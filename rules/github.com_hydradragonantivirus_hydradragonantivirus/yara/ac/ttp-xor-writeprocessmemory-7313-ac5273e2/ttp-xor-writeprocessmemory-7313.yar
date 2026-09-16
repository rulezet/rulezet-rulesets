rule TTP_XOR_WriteProcessMemory_7313 {
  strings:
    $key_7313 = { 24 61 [2] 16 43 [2] 10 76 [2] 3e 76 [2] 01 6a }

  condition:
    any of them
}