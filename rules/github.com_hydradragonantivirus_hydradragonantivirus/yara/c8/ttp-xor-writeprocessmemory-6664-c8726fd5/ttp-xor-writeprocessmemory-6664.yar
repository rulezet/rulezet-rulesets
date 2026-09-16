rule TTP_XOR_WriteProcessMemory_6664 {
  strings:
    $key_6664 = { 31 16 [2] 03 34 [2] 05 01 [2] 2b 01 [2] 14 1d }

  condition:
    any of them
}