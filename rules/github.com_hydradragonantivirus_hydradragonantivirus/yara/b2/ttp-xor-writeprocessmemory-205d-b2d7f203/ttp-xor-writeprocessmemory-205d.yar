rule TTP_XOR_WriteProcessMemory_205d {
  strings:
    $key_205d = { 77 2f [2] 45 0d [2] 43 38 [2] 6d 38 [2] 52 24 }

  condition:
    any of them
}