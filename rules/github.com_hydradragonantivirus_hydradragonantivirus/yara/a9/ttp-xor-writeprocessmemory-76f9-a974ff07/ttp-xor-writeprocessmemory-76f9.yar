rule TTP_XOR_WriteProcessMemory_76f9 {
  strings:
    $key_76f9 = { 21 8b [2] 13 a9 [2] 15 9c [2] 3b 9c [2] 04 80 }

  condition:
    any of them
}