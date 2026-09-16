rule TTP_XOR_WriteProcessMemory_e664 {
  strings:
    $key_e664 = { b1 16 [2] 83 34 [2] 85 01 [2] ab 01 [2] 94 1d }

  condition:
    any of them
}