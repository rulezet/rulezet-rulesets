rule TTP_XOR_WriteProcessMemory_303d {
  strings:
    $key_303d = { 67 4f [2] 55 6d [2] 53 58 [2] 7d 58 [2] 42 44 }

  condition:
    any of them
}