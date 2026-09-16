rule TTP_XOR_WriteProcessMemory_3e16 {
  strings:
    $key_3e16 = { 69 64 [2] 5b 46 [2] 5d 73 [2] 73 73 [2] 4c 6f }

  condition:
    any of them
}