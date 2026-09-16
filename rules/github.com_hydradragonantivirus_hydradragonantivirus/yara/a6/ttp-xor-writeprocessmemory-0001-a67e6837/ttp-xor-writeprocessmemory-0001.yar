rule TTP_XOR_WriteProcessMemory_0001 {
  strings:
    $key_0001 = { 57 73 [2] 65 51 [2] 63 64 [2] 4d 64 [2] 72 78 }

  condition:
    any of them
}