rule TTP_XOR_WriteProcessMemory_7201 {
  strings:
    $key_7201 = { 25 73 [2] 17 51 [2] 11 64 [2] 3f 64 [2] 00 78 }

  condition:
    any of them
}