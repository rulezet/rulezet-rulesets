rule TTP_XOR_WriteProcessMemory_0f01 {
  strings:
    $key_0f01 = { 58 73 [2] 6a 51 [2] 6c 64 [2] 42 64 [2] 7d 78 }

  condition:
    any of them
}