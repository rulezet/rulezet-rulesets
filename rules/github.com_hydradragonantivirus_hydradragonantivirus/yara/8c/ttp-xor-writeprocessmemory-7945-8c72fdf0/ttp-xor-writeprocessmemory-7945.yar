rule TTP_XOR_WriteProcessMemory_7945 {
  strings:
    $key_7945 = { 2e 37 [2] 1c 15 [2] 1a 20 [2] 34 20 [2] 0b 3c }

  condition:
    any of them
}