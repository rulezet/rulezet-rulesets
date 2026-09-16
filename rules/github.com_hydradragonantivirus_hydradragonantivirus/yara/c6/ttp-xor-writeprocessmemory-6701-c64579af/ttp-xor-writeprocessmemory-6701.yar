rule TTP_XOR_WriteProcessMemory_6701 {
  strings:
    $key_6701 = { 30 73 [2] 02 51 [2] 04 64 [2] 2a 64 [2] 15 78 }

  condition:
    any of them
}