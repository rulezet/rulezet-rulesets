rule TTP_XOR_WriteProcessMemory_501d {
  strings:
    $key_501d = { 07 6f [2] 35 4d [2] 33 78 [2] 1d 78 [2] 22 64 }

  condition:
    any of them
}