rule TTP_XOR_WriteProcessMemory_6d19 {
  strings:
    $key_6d19 = { 3a 6b [2] 08 49 [2] 0e 7c [2] 20 7c [2] 1f 60 }

  condition:
    any of them
}