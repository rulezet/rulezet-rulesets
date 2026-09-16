rule TTP_XOR_WriteProcessMemory_1f01 {
  strings:
    $key_1f01 = { 48 73 [2] 7a 51 [2] 7c 64 [2] 52 64 [2] 6d 78 }

  condition:
    any of them
}