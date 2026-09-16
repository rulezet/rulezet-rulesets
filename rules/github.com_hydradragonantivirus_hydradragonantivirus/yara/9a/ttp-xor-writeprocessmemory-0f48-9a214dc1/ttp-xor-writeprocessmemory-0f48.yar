rule TTP_XOR_WriteProcessMemory_0f48 {
  strings:
    $key_0f48 = { 58 3a [2] 6a 18 [2] 6c 2d [2] 42 2d [2] 7d 31 }

  condition:
    any of them
}