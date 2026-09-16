rule TTP_XOR_WriteProcessMemory_7607 {
  strings:
    $key_7607 = { 21 75 [2] 13 57 [2] 15 62 [2] 3b 62 [2] 04 7e }

  condition:
    any of them
}