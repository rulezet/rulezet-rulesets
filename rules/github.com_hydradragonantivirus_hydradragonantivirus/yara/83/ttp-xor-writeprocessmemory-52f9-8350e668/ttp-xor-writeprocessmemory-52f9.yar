rule TTP_XOR_WriteProcessMemory_52f9 {
  strings:
    $key_52f9 = { 05 8b [2] 37 a9 [2] 31 9c [2] 1f 9c [2] 20 80 }

  condition:
    any of them
}