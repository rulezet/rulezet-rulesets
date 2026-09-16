rule TTP_XOR_WriteProcessMemory_685d {
  strings:
    $key_685d = { 3f 2f [2] 0d 0d [2] 0b 38 [2] 25 38 [2] 1a 24 }

  condition:
    any of them
}