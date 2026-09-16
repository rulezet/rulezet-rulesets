rule TTP_XOR_WriteProcessMemory_6704 {
  strings:
    $key_6704 = { 30 76 [2] 02 54 [2] 04 61 [2] 2a 61 [2] 15 7d }

  condition:
    any of them
}