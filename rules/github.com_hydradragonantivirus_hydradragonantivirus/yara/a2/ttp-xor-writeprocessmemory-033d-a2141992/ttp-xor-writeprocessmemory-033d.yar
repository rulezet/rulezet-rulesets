rule TTP_XOR_WriteProcessMemory_033d {
  strings:
    $key_033d = { 54 4f [2] 66 6d [2] 60 58 [2] 4e 58 [2] 71 44 }

  condition:
    any of them
}