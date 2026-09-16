rule TTP_XOR_WriteProcessMemory_0f07 {
  strings:
    $key_0f07 = { 58 75 [2] 6a 57 [2] 6c 62 [2] 42 62 [2] 7d 7e }

  condition:
    any of them
}