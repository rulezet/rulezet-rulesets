rule TTP_XOR_WriteProcessMemory_0f4d {
  strings:
    $key_0f4d = { 58 3f [2] 6a 1d [2] 6c 28 [2] 42 28 [2] 7d 34 }

  condition:
    any of them
}