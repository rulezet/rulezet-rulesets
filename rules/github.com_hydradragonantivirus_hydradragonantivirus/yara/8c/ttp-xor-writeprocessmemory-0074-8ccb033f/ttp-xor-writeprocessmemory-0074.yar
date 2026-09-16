rule TTP_XOR_WriteProcessMemory_0074 {
  strings:
    $key_0074 = { 57 06 [2] 65 24 [2] 63 11 [2] 4d 11 [2] 72 0d }

  condition:
    any of them
}