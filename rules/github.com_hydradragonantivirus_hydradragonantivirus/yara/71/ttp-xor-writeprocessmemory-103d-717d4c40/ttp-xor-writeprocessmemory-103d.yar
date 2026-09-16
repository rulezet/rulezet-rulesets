rule TTP_XOR_WriteProcessMemory_103d {
  strings:
    $key_103d = { 47 4f [2] 75 6d [2] 73 58 [2] 5d 58 [2] 62 44 }

  condition:
    any of them
}