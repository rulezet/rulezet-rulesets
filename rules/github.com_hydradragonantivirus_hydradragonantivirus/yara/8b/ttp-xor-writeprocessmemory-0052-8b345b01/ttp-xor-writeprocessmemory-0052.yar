rule TTP_XOR_WriteProcessMemory_0052 {
  strings:
    $key_0052 = { 57 20 [2] 65 02 [2] 63 37 [2] 4d 37 [2] 72 2b }

  condition:
    any of them
}