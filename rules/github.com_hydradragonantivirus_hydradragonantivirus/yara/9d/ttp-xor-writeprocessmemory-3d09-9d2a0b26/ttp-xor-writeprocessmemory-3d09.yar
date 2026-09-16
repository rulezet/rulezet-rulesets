rule TTP_XOR_WriteProcessMemory_3d09 {
  strings:
    $key_3d09 = { 6a 7b [2] 58 59 [2] 5e 6c [2] 70 6c [2] 4f 70 }

  condition:
    any of them
}