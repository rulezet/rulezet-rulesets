rule TTP_XOR_WriteProcessMemory_5d61 {
  strings:
    $key_5d61 = { 0a 13 [2] 38 31 [2] 3e 04 [2] 10 04 [2] 2f 18 }

  condition:
    any of them
}