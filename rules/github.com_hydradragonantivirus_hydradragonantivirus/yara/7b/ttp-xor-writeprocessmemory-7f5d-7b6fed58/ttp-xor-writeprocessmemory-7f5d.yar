rule TTP_XOR_WriteProcessMemory_7f5d {
  strings:
    $key_7f5d = { 28 2f [2] 1a 0d [2] 1c 38 [2] 32 38 [2] 0d 24 }

  condition:
    any of them
}