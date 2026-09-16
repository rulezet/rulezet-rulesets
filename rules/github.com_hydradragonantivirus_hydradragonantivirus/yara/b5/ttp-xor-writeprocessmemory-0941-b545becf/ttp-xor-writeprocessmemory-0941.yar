rule TTP_XOR_WriteProcessMemory_0941 {
  strings:
    $key_0941 = { 5e 33 [2] 6c 11 [2] 6a 24 [2] 44 24 [2] 7b 38 }

  condition:
    any of them
}