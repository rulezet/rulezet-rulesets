rule TTP_XOR_WriteProcessMemory_6619 {
  strings:
    $key_6619 = { 31 6b [2] 03 49 [2] 05 7c [2] 2b 7c [2] 14 60 }

  condition:
    any of them
}