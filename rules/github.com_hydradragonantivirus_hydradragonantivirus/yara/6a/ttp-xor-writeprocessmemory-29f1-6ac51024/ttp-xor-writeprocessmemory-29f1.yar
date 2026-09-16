rule TTP_XOR_WriteProcessMemory_29f1 {
  strings:
    $key_29f1 = { 7e 83 [2] 4c a1 [2] 4a 94 [2] 64 94 [2] 5b 88 }

  condition:
    any of them
}