rule TTP_XOR_WriteProcessMemory_0a1d {
  strings:
    $key_0a1d = { 5d 6f [2] 6f 4d [2] 69 78 [2] 47 78 [2] 78 64 }

  condition:
    any of them
}