rule TTP_XOR_WriteProcessMemory_0010 {
  strings:
    $key_0010 = { 57 62 [2] 65 40 [2] 63 75 [2] 4d 75 [2] 72 69 }

  condition:
    any of them
}