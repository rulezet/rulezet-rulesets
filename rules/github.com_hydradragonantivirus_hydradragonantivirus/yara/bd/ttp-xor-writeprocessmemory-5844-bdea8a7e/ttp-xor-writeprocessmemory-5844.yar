rule TTP_XOR_WriteProcessMemory_5844 {
  strings:
    $key_5844 = { 0f 36 [2] 3d 14 [2] 3b 21 [2] 15 21 [2] 2a 3d }

  condition:
    any of them
}