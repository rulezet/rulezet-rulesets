rule TTP_XOR_WriteProcessMemory_6f5d {
  strings:
    $key_6f5d = { 38 2f [2] 0a 0d [2] 0c 38 [2] 22 38 [2] 1d 24 }

  condition:
    any of them
}