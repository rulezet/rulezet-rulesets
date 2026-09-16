rule TTP_XOR_WriteProcessMemory_7f7d {
  strings:
    $key_7f7d = { 28 0f [2] 1a 2d [2] 1c 18 [2] 32 18 [2] 0d 04 }

  condition:
    any of them
}