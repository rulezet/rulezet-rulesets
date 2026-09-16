rule TTP_XOR_WriteProcessMemory_7029 {
  strings:
    $key_7029 = { 27 5b [2] 15 79 [2] 13 4c [2] 3d 4c [2] 02 50 }

  condition:
    any of them
}