rule TTP_XOR_WriteProcessMemory_4a09 {
  strings:
    $key_4a09 = { 1d 7b [2] 2f 59 [2] 29 6c [2] 07 6c [2] 38 70 }

  condition:
    any of them
}