rule TTP_XOR_WriteProcessMemory_355d {
  strings:
    $key_355d = { 62 2f [2] 50 0d [2] 56 38 [2] 78 38 [2] 47 24 }

  condition:
    any of them
}