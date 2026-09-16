rule TTP_XOR_WriteProcessMemory_1d54 {
  strings:
    $key_1d54 = { 4a 26 [2] 78 04 [2] 7e 31 [2] 50 31 [2] 6f 2d }

  condition:
    any of them
}