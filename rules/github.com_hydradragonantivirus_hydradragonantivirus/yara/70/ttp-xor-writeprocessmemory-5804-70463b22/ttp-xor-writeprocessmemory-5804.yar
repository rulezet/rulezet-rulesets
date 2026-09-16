rule TTP_XOR_WriteProcessMemory_5804 {
  strings:
    $key_5804 = { 0f 76 [2] 3d 54 [2] 3b 61 [2] 15 61 [2] 2a 7d }

  condition:
    any of them
}