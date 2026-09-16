rule TTP_XOR_WriteProcessMemory_683d {
  strings:
    $key_683d = { 3f 4f [2] 0d 6d [2] 0b 58 [2] 25 58 [2] 1a 44 }

  condition:
    any of them
}