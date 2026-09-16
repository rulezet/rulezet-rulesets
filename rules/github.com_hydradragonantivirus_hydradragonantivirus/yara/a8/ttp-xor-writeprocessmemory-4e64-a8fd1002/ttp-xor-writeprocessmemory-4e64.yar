rule TTP_XOR_WriteProcessMemory_4e64 {
  strings:
    $key_4e64 = { 19 16 [2] 2b 34 [2] 2d 01 [2] 03 01 [2] 3c 1d }

  condition:
    any of them
}