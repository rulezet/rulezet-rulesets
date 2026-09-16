rule TTP_XOR_WriteProcessMemory_7239 {
  strings:
    $key_7239 = { 25 4b [2] 17 69 [2] 11 5c [2] 3f 5c [2] 00 40 }

  condition:
    any of them
}