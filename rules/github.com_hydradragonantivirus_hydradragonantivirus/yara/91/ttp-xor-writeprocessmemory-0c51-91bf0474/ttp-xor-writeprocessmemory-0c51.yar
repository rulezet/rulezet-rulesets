rule TTP_XOR_WriteProcessMemory_0c51 {
  strings:
    $key_0c51 = { 5b 23 [2] 69 01 [2] 6f 34 [2] 41 34 [2] 7e 28 }

  condition:
    any of them
}