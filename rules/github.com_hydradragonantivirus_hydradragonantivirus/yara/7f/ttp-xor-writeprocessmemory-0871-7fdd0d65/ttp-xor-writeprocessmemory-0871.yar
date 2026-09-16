rule TTP_XOR_WriteProcessMemory_0871 {
  strings:
    $key_0871 = { 5f 03 [2] 6d 21 [2] 6b 14 [2] 45 14 [2] 7a 08 }

  condition:
    any of them
}