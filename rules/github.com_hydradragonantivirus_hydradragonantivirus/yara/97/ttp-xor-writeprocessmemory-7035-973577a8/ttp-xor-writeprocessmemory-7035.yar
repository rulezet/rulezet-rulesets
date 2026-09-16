rule TTP_XOR_WriteProcessMemory_7035 {
  strings:
    $key_7035 = { 27 47 [2] 15 65 [2] 13 50 [2] 3d 50 [2] 02 4c }

  condition:
    any of them
}