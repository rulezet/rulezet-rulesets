rule TTP_XOR_WriteProcessMemory_4ee0 {
  strings:
    $key_4ee0 = { 19 92 [2] 2b b0 [2] 2d 85 [2] 03 85 [2] 3c 99 }

  condition:
    any of them
}