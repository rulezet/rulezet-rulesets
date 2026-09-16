rule TTP_XOR_WriteProcessMemory_6e2d {
  strings:
    $key_6e2d = { 39 5f [2] 0b 7d [2] 0d 48 [2] 23 48 [2] 1c 54 }

  condition:
    any of them
}