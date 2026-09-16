rule TTP_XOR_WriteProcessMemory_201d {
  strings:
    $key_201d = { 77 6f [2] 45 4d [2] 43 78 [2] 6d 78 [2] 52 64 }

  condition:
    any of them
}