rule TTP_XOR_WriteProcessMemory_5f7d {
  strings:
    $key_5f7d = { 08 0f [2] 3a 2d [2] 3c 18 [2] 12 18 [2] 2d 04 }

  condition:
    any of them
}