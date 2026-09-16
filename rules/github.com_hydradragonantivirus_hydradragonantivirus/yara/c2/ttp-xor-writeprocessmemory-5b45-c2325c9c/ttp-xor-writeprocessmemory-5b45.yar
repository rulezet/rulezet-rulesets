rule TTP_XOR_WriteProcessMemory_5b45 {
  strings:
    $key_5b45 = { 0c 37 [2] 3e 15 [2] 38 20 [2] 16 20 [2] 29 3c }

  condition:
    any of them
}