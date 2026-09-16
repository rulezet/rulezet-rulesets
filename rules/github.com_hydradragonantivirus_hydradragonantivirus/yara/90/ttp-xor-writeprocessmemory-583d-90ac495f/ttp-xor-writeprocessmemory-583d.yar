rule TTP_XOR_WriteProcessMemory_583d {
  strings:
    $key_583d = { 0f 4f [2] 3d 6d [2] 3b 58 [2] 15 58 [2] 2a 44 }

  condition:
    any of them
}