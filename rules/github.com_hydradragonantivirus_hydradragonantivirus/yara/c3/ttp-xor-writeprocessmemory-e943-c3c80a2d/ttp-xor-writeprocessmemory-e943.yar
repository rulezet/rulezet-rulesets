rule TTP_XOR_WriteProcessMemory_e943 {
  strings:
    $key_e943 = { be 31 [2] 8c 13 [2] 8a 26 [2] a4 26 [2] 9b 3a }

  condition:
    any of them
}