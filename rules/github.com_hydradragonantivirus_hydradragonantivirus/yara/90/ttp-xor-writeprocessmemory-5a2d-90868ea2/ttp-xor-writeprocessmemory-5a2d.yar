rule TTP_XOR_WriteProcessMemory_5a2d {
  strings:
    $key_5a2d = { 0d 5f [2] 3f 7d [2] 39 48 [2] 17 48 [2] 28 54 }

  condition:
    any of them
}