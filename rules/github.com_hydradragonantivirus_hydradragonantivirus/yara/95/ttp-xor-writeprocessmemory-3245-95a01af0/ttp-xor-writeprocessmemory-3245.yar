rule TTP_XOR_WriteProcessMemory_3245 {
  strings:
    $key_3245 = { 65 37 [2] 57 15 [2] 51 20 [2] 7f 20 [2] 40 3c }

  condition:
    any of them
}