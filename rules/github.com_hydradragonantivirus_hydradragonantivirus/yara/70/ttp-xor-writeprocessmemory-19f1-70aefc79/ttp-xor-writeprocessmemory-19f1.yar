rule TTP_XOR_WriteProcessMemory_19f1 {
  strings:
    $key_19f1 = { 4e 83 [2] 7c a1 [2] 7a 94 [2] 54 94 [2] 6b 88 }

  condition:
    any of them
}