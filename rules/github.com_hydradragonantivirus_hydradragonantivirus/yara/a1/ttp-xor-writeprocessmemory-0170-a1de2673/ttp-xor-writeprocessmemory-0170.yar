rule TTP_XOR_WriteProcessMemory_0170 {
  strings:
    $key_0170 = { 56 02 [2] 64 20 [2] 62 15 [2] 4c 15 [2] 73 09 }

  condition:
    any of them
}