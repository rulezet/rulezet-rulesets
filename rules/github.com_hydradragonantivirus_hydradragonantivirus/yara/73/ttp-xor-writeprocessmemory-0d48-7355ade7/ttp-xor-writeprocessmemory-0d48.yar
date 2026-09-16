rule TTP_XOR_WriteProcessMemory_0d48 {
  strings:
    $key_0d48 = { 5a 3a [2] 68 18 [2] 6e 2d [2] 40 2d [2] 7f 31 }

  condition:
    any of them
}