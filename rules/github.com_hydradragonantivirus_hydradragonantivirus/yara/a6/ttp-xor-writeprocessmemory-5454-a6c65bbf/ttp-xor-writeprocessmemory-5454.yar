rule TTP_XOR_WriteProcessMemory_5454 {
  strings:
    $key_5454 = { 03 26 [2] 31 04 [2] 37 31 [2] 19 31 [2] 26 2d }

  condition:
    any of them
}