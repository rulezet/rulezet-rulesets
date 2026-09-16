rule TTP_XOR_WriteProcessMemory_e63d {
  strings:
    $key_e63d = { b1 4f [2] 83 6d [2] 85 58 [2] ab 58 [2] 94 44 }

  condition:
    any of them
}