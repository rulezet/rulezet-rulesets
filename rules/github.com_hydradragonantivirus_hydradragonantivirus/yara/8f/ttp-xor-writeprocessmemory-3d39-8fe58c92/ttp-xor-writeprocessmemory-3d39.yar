rule TTP_XOR_WriteProcessMemory_3d39 {
  strings:
    $key_3d39 = { 6a 4b [2] 58 69 [2] 5e 5c [2] 70 5c [2] 4f 40 }

  condition:
    any of them
}