rule TTP_XOR_WriteProcessMemory_3935 {
  strings:
    $key_3935 = { 6e 47 [2] 5c 65 [2] 5a 50 [2] 74 50 [2] 4b 4c }

  condition:
    any of them
}