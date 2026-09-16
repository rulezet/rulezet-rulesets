rule TTP_XOR_WriteProcessMemory_3cf1 {
  strings:
    $key_3cf1 = { 6b 83 [2] 59 a1 [2] 5f 94 [2] 71 94 [2] 4e 88 }

  condition:
    any of them
}