rule TTP_XOR_WriteProcessMemory_6839 {
  strings:
    $key_6839 = { 3f 4b [2] 0d 69 [2] 0b 5c [2] 25 5c [2] 1a 40 }

  condition:
    any of them
}