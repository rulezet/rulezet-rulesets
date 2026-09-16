rule TTP_XOR_WriteProcessMemory_7209 {
  strings:
    $key_7209 = { 25 7b [2] 17 59 [2] 11 6c [2] 3f 6c [2] 00 70 }

  condition:
    any of them
}