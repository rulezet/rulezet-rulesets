rule TTP_XOR_WriteProcessMemory_3d59 {
  strings:
    $key_3d59 = { 6a 2b [2] 58 09 [2] 5e 3c [2] 70 3c [2] 4f 20 }

  condition:
    any of them
}