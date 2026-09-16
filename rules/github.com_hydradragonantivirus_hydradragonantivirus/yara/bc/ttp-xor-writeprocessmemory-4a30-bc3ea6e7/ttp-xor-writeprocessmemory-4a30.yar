rule TTP_XOR_WriteProcessMemory_4a30 {
  strings:
    $key_4a30 = { 1d 42 [2] 2f 60 [2] 29 55 [2] 07 55 [2] 38 49 }

  condition:
    any of them
}