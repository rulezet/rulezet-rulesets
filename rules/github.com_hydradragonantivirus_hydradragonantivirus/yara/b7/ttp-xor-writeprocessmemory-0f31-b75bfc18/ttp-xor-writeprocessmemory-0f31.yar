rule TTP_XOR_WriteProcessMemory_0f31 {
  strings:
    $key_0f31 = { 58 43 [2] 6a 61 [2] 6c 54 [2] 42 54 [2] 7d 48 }

  condition:
    any of them
}