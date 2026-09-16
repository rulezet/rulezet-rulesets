rule TTP_XOR_WriteProcessMemory_2459 {
  strings:
    $key_2459 = { 73 2b [2] 41 09 [2] 47 3c [2] 69 3c [2] 56 20 }

  condition:
    any of them
}