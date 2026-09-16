rule TTP_XOR_WriteProcessMemory_24e9 {
  strings:
    $key_24e9 = { 73 9b [2] 41 b9 [2] 47 8c [2] 69 8c [2] 56 90 }

  condition:
    any of them
}