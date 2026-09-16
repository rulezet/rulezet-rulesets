rule TTP_XOR_WriteProcessMemory_7219 {
  strings:
    $key_7219 = { 25 6b [2] 17 49 [2] 11 7c [2] 3f 7c [2] 00 60 }

  condition:
    any of them
}