rule TTP_XOR_WriteProcessMemory_2830 {
  strings:
    $key_2830 = { 7f 42 [2] 4d 60 [2] 4b 55 [2] 65 55 [2] 5a 49 }

  condition:
    any of them
}