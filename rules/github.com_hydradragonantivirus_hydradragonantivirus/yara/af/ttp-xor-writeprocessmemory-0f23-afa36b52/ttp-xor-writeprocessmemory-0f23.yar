rule TTP_XOR_WriteProcessMemory_0f23 {
  strings:
    $key_0f23 = { 58 51 [2] 6a 73 [2] 6c 46 [2] 42 46 [2] 7d 5a }

  condition:
    any of them
}