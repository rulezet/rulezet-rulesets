rule TTP_XOR_WriteProcessMemory_0a51 {
  strings:
    $key_0a51 = { 5d 23 [2] 6f 01 [2] 69 34 [2] 47 34 [2] 78 28 }

  condition:
    any of them
}