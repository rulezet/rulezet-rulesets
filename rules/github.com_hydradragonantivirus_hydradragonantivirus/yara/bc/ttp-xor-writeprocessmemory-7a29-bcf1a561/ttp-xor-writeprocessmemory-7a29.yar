rule TTP_XOR_WriteProcessMemory_7a29 {
  strings:
    $key_7a29 = { 2d 5b [2] 1f 79 [2] 19 4c [2] 37 4c [2] 08 50 }

  condition:
    any of them
}