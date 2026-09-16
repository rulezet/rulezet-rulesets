rule TTP_XOR_WriteProcessMemory_1654 {
  strings:
    $key_1654 = { 41 26 [2] 73 04 [2] 75 31 [2] 5b 31 [2] 64 2d }

  condition:
    any of them
}