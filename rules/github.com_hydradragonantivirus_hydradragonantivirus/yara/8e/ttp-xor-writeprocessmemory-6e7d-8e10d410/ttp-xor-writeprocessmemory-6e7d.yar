rule TTP_XOR_WriteProcessMemory_6e7d {
  strings:
    $key_6e7d = { 39 0f [2] 0b 2d [2] 0d 18 [2] 23 18 [2] 1c 04 }

  condition:
    any of them
}