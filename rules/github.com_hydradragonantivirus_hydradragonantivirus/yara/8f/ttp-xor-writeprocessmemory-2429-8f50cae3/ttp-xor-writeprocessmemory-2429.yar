rule TTP_XOR_WriteProcessMemory_2429 {
  strings:
    $key_2429 = { 73 5b [2] 41 79 [2] 47 4c [2] 69 4c [2] 56 50 }

  condition:
    any of them
}