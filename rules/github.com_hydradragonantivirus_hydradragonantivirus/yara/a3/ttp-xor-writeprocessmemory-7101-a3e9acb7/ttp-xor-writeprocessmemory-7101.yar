rule TTP_XOR_WriteProcessMemory_7101 {
  strings:
    $key_7101 = { 26 73 [2] 14 51 [2] 12 64 [2] 3c 64 [2] 03 78 }

  condition:
    any of them
}