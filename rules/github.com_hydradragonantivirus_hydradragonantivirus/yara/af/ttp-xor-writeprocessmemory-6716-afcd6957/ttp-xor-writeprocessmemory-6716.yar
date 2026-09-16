rule TTP_XOR_WriteProcessMemory_6716 {
  strings:
    $key_6716 = { 30 64 [2] 02 46 [2] 04 73 [2] 2a 73 [2] 15 6f }

  condition:
    any of them
}