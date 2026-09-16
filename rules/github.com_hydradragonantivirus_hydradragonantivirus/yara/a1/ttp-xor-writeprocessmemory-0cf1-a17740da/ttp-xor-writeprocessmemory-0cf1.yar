rule TTP_XOR_WriteProcessMemory_0cf1 {
  strings:
    $key_0cf1 = { 5b 83 [2] 69 a1 [2] 6f 94 [2] 41 94 [2] 7e 88 }

  condition:
    any of them
}