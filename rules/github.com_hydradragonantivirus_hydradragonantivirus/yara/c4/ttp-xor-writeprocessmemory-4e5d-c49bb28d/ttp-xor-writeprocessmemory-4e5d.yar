rule TTP_XOR_WriteProcessMemory_4e5d {
  strings:
    $key_4e5d = { 19 2f [2] 2b 0d [2] 2d 38 [2] 03 38 [2] 3c 24 }

  condition:
    any of them
}