rule TTP_XOR_WriteProcessMemory_4145 {
  strings:
    $key_4145 = { 16 37 [2] 24 15 [2] 22 20 [2] 0c 20 [2] 33 3c }

  condition:
    any of them
}