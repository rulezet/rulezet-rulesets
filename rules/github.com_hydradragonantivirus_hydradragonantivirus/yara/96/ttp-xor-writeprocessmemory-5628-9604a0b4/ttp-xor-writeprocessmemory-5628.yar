rule TTP_XOR_WriteProcessMemory_5628 {
  strings:
    $key_5628 = { 01 5a [2] 33 78 [2] 35 4d [2] 1b 4d [2] 24 51 }

  condition:
    any of them
}