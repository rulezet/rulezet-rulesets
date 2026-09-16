rule TTP_XOR_WriteProcessMemory_52e9 {
  strings:
    $key_52e9 = { 05 9b [2] 37 b9 [2] 31 8c [2] 1f 8c [2] 20 90 }

  condition:
    any of them
}