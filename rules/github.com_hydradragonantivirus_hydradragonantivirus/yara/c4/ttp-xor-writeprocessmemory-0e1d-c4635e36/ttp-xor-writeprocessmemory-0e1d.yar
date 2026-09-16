rule TTP_XOR_WriteProcessMemory_0e1d {
  strings:
    $key_0e1d = { 59 6f [2] 6b 4d [2] 6d 78 [2] 43 78 [2] 7c 64 }

  condition:
    any of them
}