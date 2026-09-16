rule TTP_XOR_WriteProcessMemory_641d {
  strings:
    $key_641d = { 33 6f [2] 01 4d [2] 07 78 [2] 29 78 [2] 16 64 }

  condition:
    any of them
}