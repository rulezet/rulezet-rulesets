rule TTP_XOR_WriteProcessMemory_6654 {
  strings:
    $key_6654 = { 31 26 [2] 03 04 [2] 05 31 [2] 2b 31 [2] 14 2d }

  condition:
    any of them
}