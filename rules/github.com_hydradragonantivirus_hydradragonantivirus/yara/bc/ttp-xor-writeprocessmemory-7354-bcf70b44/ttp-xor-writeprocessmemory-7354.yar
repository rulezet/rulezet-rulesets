rule TTP_XOR_WriteProcessMemory_7354 {
  strings:
    $key_7354 = { 24 26 [2] 16 04 [2] 10 31 [2] 3e 31 [2] 01 2d }

  condition:
    any of them
}