rule TTP_XOR_WriteProcessMemory_5879 {
  strings:
    $key_5879 = { 0f 0b [2] 3d 29 [2] 3b 1c [2] 15 1c [2] 2a 00 }

  condition:
    any of them
}