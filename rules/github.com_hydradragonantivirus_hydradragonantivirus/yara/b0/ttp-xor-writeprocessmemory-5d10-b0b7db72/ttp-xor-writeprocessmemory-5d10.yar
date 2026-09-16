rule TTP_XOR_WriteProcessMemory_5d10 {
  strings:
    $key_5d10 = { 0a 62 [2] 38 40 [2] 3e 75 [2] 10 75 [2] 2f 69 }

  condition:
    any of them
}