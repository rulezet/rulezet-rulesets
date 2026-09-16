rule TTP_XOR_WriteProcessMemory_5831 {
  strings:
    $key_5831 = { 0f 43 [2] 3d 61 [2] 3b 54 [2] 15 54 [2] 2a 48 }

  condition:
    any of them
}