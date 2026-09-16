rule TTP_XOR_WriteProcessMemory_6773 {
  strings:
    $key_6773 = { 30 01 [2] 02 23 [2] 04 16 [2] 2a 16 [2] 15 0a }

  condition:
    any of them
}