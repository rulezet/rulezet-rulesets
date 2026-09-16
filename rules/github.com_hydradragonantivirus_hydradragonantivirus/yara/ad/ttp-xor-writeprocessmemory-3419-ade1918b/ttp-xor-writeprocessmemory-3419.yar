rule TTP_XOR_WriteProcessMemory_3419 {
  strings:
    $key_3419 = { 63 6b [2] 51 49 [2] 57 7c [2] 79 7c [2] 46 60 }

  condition:
    any of them
}