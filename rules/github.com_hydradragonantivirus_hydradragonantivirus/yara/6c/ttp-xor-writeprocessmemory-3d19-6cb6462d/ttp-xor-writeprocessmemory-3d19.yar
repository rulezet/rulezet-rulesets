rule TTP_XOR_WriteProcessMemory_3d19 {
  strings:
    $key_3d19 = { 6a 6b [2] 58 49 [2] 5e 7c [2] 70 7c [2] 4f 60 }

  condition:
    any of them
}