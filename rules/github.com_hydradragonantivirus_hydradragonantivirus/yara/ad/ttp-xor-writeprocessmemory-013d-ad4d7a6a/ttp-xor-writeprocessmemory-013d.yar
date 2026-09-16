rule TTP_XOR_WriteProcessMemory_013d {
  strings:
    $key_013d = { 56 4f [2] 64 6d [2] 62 58 [2] 4c 58 [2] 73 44 }

  condition:
    any of them
}