rule TTP_XOR_WriteProcessMemory_5919 {
  strings:
    $key_5919 = { 0e 6b [2] 3c 49 [2] 3a 7c [2] 14 7c [2] 2b 60 }

  condition:
    any of them
}