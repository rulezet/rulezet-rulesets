rule TTP_XOR_WriteProcessMemory_1e1d {
  strings:
    $key_1e1d = { 49 6f [2] 7b 4d [2] 7d 78 [2] 53 78 [2] 6c 64 }

  condition:
    any of them
}