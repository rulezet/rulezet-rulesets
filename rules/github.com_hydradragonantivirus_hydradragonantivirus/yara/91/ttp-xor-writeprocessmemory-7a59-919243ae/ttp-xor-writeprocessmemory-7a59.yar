rule TTP_XOR_WriteProcessMemory_7a59 {
  strings:
    $key_7a59 = { 2d 2b [2] 1f 09 [2] 19 3c [2] 37 3c [2] 08 20 }

  condition:
    any of them
}