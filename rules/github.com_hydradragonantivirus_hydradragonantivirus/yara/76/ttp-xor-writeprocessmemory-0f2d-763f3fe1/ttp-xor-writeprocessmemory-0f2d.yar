rule TTP_XOR_WriteProcessMemory_0f2d {
  strings:
    $key_0f2d = { 58 5f [2] 6a 7d [2] 6c 48 [2] 42 48 [2] 7d 54 }

  condition:
    any of them
}