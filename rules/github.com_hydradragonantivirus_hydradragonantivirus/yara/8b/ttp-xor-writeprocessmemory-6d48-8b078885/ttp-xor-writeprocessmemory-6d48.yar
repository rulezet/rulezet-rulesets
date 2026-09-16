rule TTP_XOR_WriteProcessMemory_6d48 {
  strings:
    $key_6d48 = { 3a 3a [2] 08 18 [2] 0e 2d [2] 20 2d [2] 1f 31 }

  condition:
    any of them
}