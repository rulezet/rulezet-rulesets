rule TTP_XOR_WriteProcessMemory_4e7d {
  strings:
    $key_4e7d = { 19 0f [2] 2b 2d [2] 2d 18 [2] 03 18 [2] 3c 04 }

  condition:
    any of them
}