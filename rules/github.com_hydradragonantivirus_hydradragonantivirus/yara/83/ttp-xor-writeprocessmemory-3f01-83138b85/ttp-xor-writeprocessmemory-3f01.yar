rule TTP_XOR_WriteProcessMemory_3f01 {
  strings:
    $key_3f01 = { 68 73 [2] 5a 51 [2] 5c 64 [2] 72 64 [2] 4d 78 }

  condition:
    any of them
}