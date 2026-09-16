rule TTP_XOR_WriteProcessMemory_6e1d {
  strings:
    $key_6e1d = { 39 6f [2] 0b 4d [2] 0d 78 [2] 23 78 [2] 1c 64 }

  condition:
    any of them
}