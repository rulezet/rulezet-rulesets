rule TTP_XOR_WriteProcessMemory_3b45 {
  strings:
    $key_3b45 = { 6c 37 [2] 5e 15 [2] 58 20 [2] 76 20 [2] 49 3c }

  condition:
    any of them
}