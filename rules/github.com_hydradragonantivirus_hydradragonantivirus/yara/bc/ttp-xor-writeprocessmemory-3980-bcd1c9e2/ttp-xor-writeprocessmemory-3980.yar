rule TTP_XOR_WriteProcessMemory_3980 {
  strings:
    $key_3980 = { 6e f2 [2] 5c d0 [2] 5a e5 [2] 74 e5 [2] 4b f9 }

  condition:
    any of them
}