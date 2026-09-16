rule TTP_XOR_WriteProcessMemory_2861 {
  strings:
    $key_2861 = { 7f 13 [2] 4d 31 [2] 4b 04 [2] 65 04 [2] 5a 18 }

  condition:
    any of them
}