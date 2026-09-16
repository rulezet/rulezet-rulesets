rule TTP_XOR_WriteProcessMemory_6864 {
  strings:
    $key_6864 = { 3f 16 [2] 0d 34 [2] 0b 01 [2] 25 01 [2] 1a 1d }

  condition:
    any of them
}