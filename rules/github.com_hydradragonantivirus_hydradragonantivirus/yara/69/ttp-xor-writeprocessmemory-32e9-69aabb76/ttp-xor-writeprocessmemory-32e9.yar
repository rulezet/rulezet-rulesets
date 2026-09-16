rule TTP_XOR_WriteProcessMemory_32e9 {
  strings:
    $key_32e9 = { 65 9b [2] 57 b9 [2] 51 8c [2] 7f 8c [2] 40 90 }

  condition:
    any of them
}