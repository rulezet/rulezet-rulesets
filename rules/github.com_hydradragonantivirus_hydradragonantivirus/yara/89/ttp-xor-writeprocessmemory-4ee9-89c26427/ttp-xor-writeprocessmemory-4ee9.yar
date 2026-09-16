rule TTP_XOR_WriteProcessMemory_4ee9 {
  strings:
    $key_4ee9 = { 19 9b [2] 2b b9 [2] 2d 8c [2] 03 8c [2] 3c 90 }

  condition:
    any of them
}