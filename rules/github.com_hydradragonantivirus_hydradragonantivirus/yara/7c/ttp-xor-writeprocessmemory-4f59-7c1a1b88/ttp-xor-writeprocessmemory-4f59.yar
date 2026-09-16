rule TTP_XOR_WriteProcessMemory_4f59 {
  strings:
    $key_4f59 = { 18 2b [2] 2a 09 [2] 2c 3c [2] 02 3c [2] 3d 20 }

  condition:
    any of them
}