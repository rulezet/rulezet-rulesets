rule TTP_XOR_WriteProcessMemory_5401 {
  strings:
    $key_5401 = { 03 73 [2] 31 51 [2] 37 64 [2] 19 64 [2] 26 78 }

  condition:
    any of them
}