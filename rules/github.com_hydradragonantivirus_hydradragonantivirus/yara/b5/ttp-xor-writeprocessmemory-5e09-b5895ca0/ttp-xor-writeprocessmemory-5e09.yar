rule TTP_XOR_WriteProcessMemory_5e09 {
  strings:
    $key_5e09 = { 09 7b [2] 3b 59 [2] 3d 6c [2] 13 6c [2] 2c 70 }

  condition:
    any of them
}