rule TTP_XOR_WriteProcessMemory_6723 {
  strings:
    $key_6723 = { 30 51 [2] 02 73 [2] 04 46 [2] 2a 46 [2] 15 5a }

  condition:
    any of them
}