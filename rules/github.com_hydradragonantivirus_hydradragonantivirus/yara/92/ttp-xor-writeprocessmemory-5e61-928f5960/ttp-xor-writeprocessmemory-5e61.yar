rule TTP_XOR_WriteProcessMemory_5e61 {
  strings:
    $key_5e61 = { 09 13 [2] 3b 31 [2] 3d 04 [2] 13 04 [2] 2c 18 }

  condition:
    any of them
}