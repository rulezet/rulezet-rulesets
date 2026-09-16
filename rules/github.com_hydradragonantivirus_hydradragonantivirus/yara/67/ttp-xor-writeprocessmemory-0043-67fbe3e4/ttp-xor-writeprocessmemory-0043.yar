rule TTP_XOR_WriteProcessMemory_0043 {
  strings:
    $key_0043 = { 57 31 [2] 65 13 [2] 63 26 [2] 4d 26 [2] 72 3a }

  condition:
    any of them
}