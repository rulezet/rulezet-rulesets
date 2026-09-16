rule TTP_XOR_WriteProcessMemory_24f9 {
  strings:
    $key_24f9 = { 73 8b [2] 41 a9 [2] 47 9c [2] 69 9c [2] 56 80 }

  condition:
    any of them
}