rule TTP_XOR_WriteProcessMemory_155d {
  strings:
    $key_155d = { 42 2f [2] 70 0d [2] 76 38 [2] 58 38 [2] 67 24 }

  condition:
    any of them
}