rule TTP_XOR_WriteProcessMemory_2ee0 {
  strings:
    $key_2ee0 = { 79 92 [2] 4b b0 [2] 4d 85 [2] 63 85 [2] 5c 99 }

  condition:
    any of them
}