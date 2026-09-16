rule TTP_XOR_WriteProcessMemory_7ae9 {
  strings:
    $key_7ae9 = { 2d 9b [2] 1f b9 [2] 19 8c [2] 37 8c [2] 08 90 }

  condition:
    any of them
}