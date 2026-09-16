rule TTP_XOR_WriteProcessMemory_4a54 {
  strings:
    $key_4a54 = { 1d 26 [2] 2f 04 [2] 29 31 [2] 07 31 [2] 38 2d }

  condition:
    any of them
}