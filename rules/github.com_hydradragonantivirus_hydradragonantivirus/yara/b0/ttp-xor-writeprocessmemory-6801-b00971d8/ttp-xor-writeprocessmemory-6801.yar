rule TTP_XOR_WriteProcessMemory_6801 {
  strings:
    $key_6801 = { 3f 73 [2] 0d 51 [2] 0b 64 [2] 25 64 [2] 1a 78 }

  condition:
    any of them
}