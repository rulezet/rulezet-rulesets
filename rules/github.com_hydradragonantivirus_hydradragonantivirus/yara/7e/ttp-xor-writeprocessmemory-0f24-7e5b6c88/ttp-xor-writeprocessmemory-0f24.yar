rule TTP_XOR_WriteProcessMemory_0f24 {
  strings:
    $key_0f24 = { 58 56 [2] 6a 74 [2] 6c 41 [2] 42 41 [2] 7d 5d }

  condition:
    any of them
}