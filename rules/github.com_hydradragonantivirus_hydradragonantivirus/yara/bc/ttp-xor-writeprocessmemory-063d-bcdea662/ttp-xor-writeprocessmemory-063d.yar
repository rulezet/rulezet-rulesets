rule TTP_XOR_WriteProcessMemory_063d {
  strings:
    $key_063d = { 51 4f [2] 63 6d [2] 65 58 [2] 4b 58 [2] 74 44 }

  condition:
    any of them
}