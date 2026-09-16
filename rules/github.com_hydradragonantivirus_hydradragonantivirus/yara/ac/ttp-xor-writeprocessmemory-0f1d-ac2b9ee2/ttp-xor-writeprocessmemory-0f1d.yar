rule TTP_XOR_WriteProcessMemory_0f1d {
  strings:
    $key_0f1d = { 58 6f [2] 6a 4d [2] 6c 78 [2] 42 78 [2] 7d 64 }

  condition:
    any of them
}