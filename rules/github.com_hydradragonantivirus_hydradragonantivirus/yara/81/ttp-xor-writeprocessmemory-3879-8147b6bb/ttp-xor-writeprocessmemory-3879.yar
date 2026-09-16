rule TTP_XOR_WriteProcessMemory_3879 {
  strings:
    $key_3879 = { 6f 0b [2] 5d 29 [2] 5b 1c [2] 75 1c [2] 4a 00 }

  condition:
    any of them
}