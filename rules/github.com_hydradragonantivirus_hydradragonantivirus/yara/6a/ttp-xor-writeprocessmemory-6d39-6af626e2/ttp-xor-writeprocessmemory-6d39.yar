rule TTP_XOR_WriteProcessMemory_6d39 {
  strings:
    $key_6d39 = { 3a 4b [2] 08 69 [2] 0e 5c [2] 20 5c [2] 1f 40 }

  condition:
    any of them
}