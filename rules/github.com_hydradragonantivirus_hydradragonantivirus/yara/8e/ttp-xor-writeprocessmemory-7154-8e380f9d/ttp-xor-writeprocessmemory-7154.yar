rule TTP_XOR_WriteProcessMemory_7154 {
  strings:
    $key_7154 = { 26 26 [2] 14 04 [2] 12 31 [2] 3c 31 [2] 03 2d }

  condition:
    any of them
}