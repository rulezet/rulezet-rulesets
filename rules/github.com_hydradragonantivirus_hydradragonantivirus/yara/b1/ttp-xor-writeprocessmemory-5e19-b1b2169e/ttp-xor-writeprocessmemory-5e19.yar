rule TTP_XOR_WriteProcessMemory_5e19 {
  strings:
    $key_5e19 = { 09 6b [2] 3b 49 [2] 3d 7c [2] 13 7c [2] 2c 60 }

  condition:
    any of them
}