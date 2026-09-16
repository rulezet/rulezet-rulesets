rule TTP_XOR_WriteProcessMemory_0101 {
  strings:
    $key_0101 = { 56 73 [2] 64 51 [2] 62 64 [2] 4c 64 [2] 73 78 }

  condition:
    any of them
}