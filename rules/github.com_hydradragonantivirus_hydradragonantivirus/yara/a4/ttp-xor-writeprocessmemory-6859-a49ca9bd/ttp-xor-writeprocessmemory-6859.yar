rule TTP_XOR_WriteProcessMemory_6859 {
  strings:
    $key_6859 = { 3f 2b [2] 0d 09 [2] 0b 3c [2] 25 3c [2] 1a 20 }

  condition:
    any of them
}