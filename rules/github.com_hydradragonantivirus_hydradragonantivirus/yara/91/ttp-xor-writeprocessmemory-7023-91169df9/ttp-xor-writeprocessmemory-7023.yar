rule TTP_XOR_WriteProcessMemory_7023 {
  strings:
    $key_7023 = { 27 51 [2] 15 73 [2] 13 46 [2] 3d 46 [2] 02 5a }

  condition:
    any of them
}