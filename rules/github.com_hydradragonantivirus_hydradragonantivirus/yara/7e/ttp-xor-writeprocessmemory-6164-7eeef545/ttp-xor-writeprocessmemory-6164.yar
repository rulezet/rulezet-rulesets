rule TTP_XOR_WriteProcessMemory_6164 {
  strings:
    $key_6164 = { 36 16 [2] 04 34 [2] 02 01 [2] 2c 01 [2] 13 1d }

  condition:
    any of them
}