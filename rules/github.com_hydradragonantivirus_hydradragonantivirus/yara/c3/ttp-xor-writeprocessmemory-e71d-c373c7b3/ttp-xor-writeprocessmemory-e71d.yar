rule TTP_XOR_WriteProcessMemory_e71d {
  strings:
    $key_e71d = { b0 6f [2] 82 4d [2] 84 78 [2] aa 78 [2] 95 64 }

  condition:
    any of them
}