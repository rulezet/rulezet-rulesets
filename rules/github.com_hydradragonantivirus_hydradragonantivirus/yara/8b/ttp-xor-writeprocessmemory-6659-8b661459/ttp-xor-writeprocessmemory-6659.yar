rule TTP_XOR_WriteProcessMemory_6659 {
  strings:
    $key_6659 = { 31 2b [2] 03 09 [2] 05 3c [2] 2b 3c [2] 14 20 }

  condition:
    any of them
}