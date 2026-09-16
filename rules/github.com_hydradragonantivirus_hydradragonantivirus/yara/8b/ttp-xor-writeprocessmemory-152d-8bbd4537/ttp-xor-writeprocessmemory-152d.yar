rule TTP_XOR_WriteProcessMemory_152d {
  strings:
    $key_152d = { 42 5f [2] 70 7d [2] 76 48 [2] 58 48 [2] 67 54 }

  condition:
    any of them
}