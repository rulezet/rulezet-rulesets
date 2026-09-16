rule TTP_XOR_WriteProcessMemory_5841 {
  strings:
    $key_5841 = { 0f 33 [2] 3d 11 [2] 3b 24 [2] 15 24 [2] 2a 38 }

  condition:
    any of them
}