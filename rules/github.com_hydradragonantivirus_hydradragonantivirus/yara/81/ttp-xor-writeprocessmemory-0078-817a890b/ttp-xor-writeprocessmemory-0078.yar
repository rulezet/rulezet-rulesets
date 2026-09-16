rule TTP_XOR_WriteProcessMemory_0078 {
  strings:
    $key_0078 = { 57 0a [2] 65 28 [2] 63 1d [2] 4d 1d [2] 72 01 }

  condition:
    any of them
}