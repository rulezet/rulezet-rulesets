rule TTP_XOR_WriteProcessMemory_7a09 {
  strings:
    $key_7a09 = { 2d 7b [2] 1f 59 [2] 19 6c [2] 37 6c [2] 08 70 }

  condition:
    any of them
}