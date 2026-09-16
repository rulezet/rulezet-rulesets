rule TTP_XOR_WriteProcessMemory_7ee0 {
  strings:
    $key_7ee0 = { 29 92 [2] 1b b0 [2] 1d 85 [2] 33 85 [2] 0c 99 }

  condition:
    any of them
}