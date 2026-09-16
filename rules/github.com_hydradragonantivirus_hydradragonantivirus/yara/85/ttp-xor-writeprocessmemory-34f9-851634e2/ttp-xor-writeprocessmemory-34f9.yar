rule TTP_XOR_WriteProcessMemory_34f9 {
  strings:
    $key_34f9 = { 63 8b [2] 51 a9 [2] 57 9c [2] 79 9c [2] 46 80 }

  condition:
    any of them
}