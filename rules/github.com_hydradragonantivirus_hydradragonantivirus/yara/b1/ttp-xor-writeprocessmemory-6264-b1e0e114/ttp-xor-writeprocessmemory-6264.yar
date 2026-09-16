rule TTP_XOR_WriteProcessMemory_6264 {
  strings:
    $key_6264 = { 35 16 [2] 07 34 [2] 01 01 [2] 2f 01 [2] 10 1d }

  condition:
    any of them
}