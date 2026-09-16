rule TTP_XOR_WriteProcessMemory_70dd {
  strings:
    $key_70dd = { 27 af [2] 15 8d [2] 13 b8 [2] 3d b8 [2] 02 a4 }

  condition:
    any of them
}