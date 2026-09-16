rule TTP_XOR_WriteProcessMemory_5528 {
  strings:
    $key_5528 = { 02 5a [2] 30 78 [2] 36 4d [2] 18 4d [2] 27 51 }

  condition:
    any of them
}