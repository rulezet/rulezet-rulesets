rule TTP_XOR_WriteProcessMemory_160d {
  strings:
    $key_160d = { 41 7f [2] 73 5d [2] 75 68 [2] 5b 68 [2] 64 74 }

  condition:
    any of them
}