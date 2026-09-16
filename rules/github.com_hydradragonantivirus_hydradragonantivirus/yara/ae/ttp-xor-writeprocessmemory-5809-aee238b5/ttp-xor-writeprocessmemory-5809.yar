rule TTP_XOR_WriteProcessMemory_5809 {
  strings:
    $key_5809 = { 0f 7b [2] 3d 59 [2] 3b 6c [2] 15 6c [2] 2a 70 }

  condition:
    any of them
}