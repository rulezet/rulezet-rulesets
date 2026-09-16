rule TTP_XOR_WriteProcessMemory_7617 {
  strings:
    $key_7617 = { 21 65 [2] 13 47 [2] 15 72 [2] 3b 72 [2] 04 6e }

  condition:
    any of them
}