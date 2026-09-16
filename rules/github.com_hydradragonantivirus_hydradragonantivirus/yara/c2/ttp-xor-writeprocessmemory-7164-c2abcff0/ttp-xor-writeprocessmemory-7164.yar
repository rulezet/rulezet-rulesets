rule TTP_XOR_WriteProcessMemory_7164 {
  strings:
    $key_7164 = { 26 16 [2] 14 34 [2] 12 01 [2] 3c 01 [2] 03 1d }

  condition:
    any of them
}