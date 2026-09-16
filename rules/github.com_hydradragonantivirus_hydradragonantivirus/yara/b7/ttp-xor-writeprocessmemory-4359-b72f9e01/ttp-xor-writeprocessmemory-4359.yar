rule TTP_XOR_WriteProcessMemory_4359 {
  strings:
    $key_4359 = { 14 2b [2] 26 09 [2] 20 3c [2] 0e 3c [2] 31 20 }

  condition:
    any of them
}