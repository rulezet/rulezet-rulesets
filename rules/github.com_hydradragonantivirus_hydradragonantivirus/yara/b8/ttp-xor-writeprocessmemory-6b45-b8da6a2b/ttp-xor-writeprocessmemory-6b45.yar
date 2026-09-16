rule TTP_XOR_WriteProcessMemory_6b45 {
  strings:
    $key_6b45 = { 3c 37 [2] 0e 15 [2] 08 20 [2] 26 20 [2] 19 3c }

  condition:
    any of them
}