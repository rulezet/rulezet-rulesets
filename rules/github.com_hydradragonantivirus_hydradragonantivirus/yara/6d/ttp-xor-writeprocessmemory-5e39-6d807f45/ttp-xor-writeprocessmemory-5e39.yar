rule TTP_XOR_WriteProcessMemory_5e39 {
  strings:
    $key_5e39 = { 09 4b [2] 3b 69 [2] 3d 5c [2] 13 5c [2] 2c 40 }

  condition:
    any of them
}