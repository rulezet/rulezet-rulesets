rule TTP_XOR_WriteProcessMemory_e654 {
  strings:
    $key_e654 = { b1 26 [2] 83 04 [2] 85 31 [2] ab 31 [2] 94 2d }

  condition:
    any of them
}