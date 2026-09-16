rule TTP_XOR_WriteProcessMemory_5d48 {
  strings:
    $key_5d48 = { 0a 3a [2] 38 18 [2] 3e 2d [2] 10 2d [2] 2f 31 }

  condition:
    any of them
}