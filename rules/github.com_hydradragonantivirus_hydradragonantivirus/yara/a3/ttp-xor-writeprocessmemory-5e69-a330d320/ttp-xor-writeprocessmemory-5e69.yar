rule TTP_XOR_WriteProcessMemory_5e69 {
  strings:
    $key_5e69 = { 09 1b [2] 3b 39 [2] 3d 0c [2] 13 0c [2] 2c 10 }

  condition:
    any of them
}