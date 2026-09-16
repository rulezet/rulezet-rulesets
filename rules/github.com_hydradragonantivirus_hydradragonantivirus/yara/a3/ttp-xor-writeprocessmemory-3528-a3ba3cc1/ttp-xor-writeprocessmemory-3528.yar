rule TTP_XOR_WriteProcessMemory_3528 {
  strings:
    $key_3528 = { 62 5a [2] 50 78 [2] 56 4d [2] 78 4d [2] 47 51 }

  condition:
    any of them
}