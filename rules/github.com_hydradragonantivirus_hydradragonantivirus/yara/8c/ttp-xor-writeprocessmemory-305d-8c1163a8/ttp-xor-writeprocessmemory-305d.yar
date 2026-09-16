rule TTP_XOR_WriteProcessMemory_305d {
  strings:
    $key_305d = { 67 2f [2] 55 0d [2] 53 38 [2] 7d 38 [2] 42 24 }

  condition:
    any of them
}