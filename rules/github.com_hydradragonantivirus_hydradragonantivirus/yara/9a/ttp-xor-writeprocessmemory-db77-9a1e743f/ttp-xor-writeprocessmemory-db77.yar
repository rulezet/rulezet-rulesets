rule TTP_XOR_WriteProcessMemory_db77 {
  strings:
    $key_db77 = { 8c 05 [2] be 27 [2] b8 12 [2] 96 12 [2] a9 0e }

  condition:
    any of them
}