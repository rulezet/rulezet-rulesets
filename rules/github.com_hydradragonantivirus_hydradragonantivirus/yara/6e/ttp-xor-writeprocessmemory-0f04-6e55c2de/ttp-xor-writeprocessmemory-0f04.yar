rule TTP_XOR_WriteProcessMemory_0f04 {
  strings:
    $key_0f04 = { 58 76 [2] 6a 54 [2] 6c 61 [2] 42 61 [2] 7d 7d }

  condition:
    any of them
}