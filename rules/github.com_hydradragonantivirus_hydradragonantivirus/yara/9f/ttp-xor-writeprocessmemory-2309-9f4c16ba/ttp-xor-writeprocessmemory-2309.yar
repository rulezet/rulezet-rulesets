rule TTP_XOR_WriteProcessMemory_2309 {
  strings:
    $key_2309 = { 74 7b [2] 46 59 [2] 40 6c [2] 6e 6c [2] 51 70 }

  condition:
    any of them
}