rule TTP_XOR_WriteProcessMemory_4a20 {
  strings:
    $key_4a20 = { 1d 52 [2] 2f 70 [2] 29 45 [2] 07 45 [2] 38 59 }

  condition:
    any of them
}