rule TTP_XOR_WriteProcessMemory_5870 {
  strings:
    $key_5870 = { 0f 02 [2] 3d 20 [2] 3b 15 [2] 15 15 [2] 2a 09 }

  condition:
    any of them
}