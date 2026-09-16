rule TTP_XOR_WriteProcessMemory_7859 {
  strings:
    $key_7859 = { 2f 2b [2] 1d 09 [2] 1b 3c [2] 35 3c [2] 0a 20 }

  condition:
    any of them
}