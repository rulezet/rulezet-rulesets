rule TTP_XOR_WriteProcessMemory_4545 {
  strings:
    $key_4545 = { 12 37 [2] 20 15 [2] 26 20 [2] 08 20 [2] 37 3c }

  condition:
    any of them
}