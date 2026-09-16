rule TTP_XOR_WriteProcessMemory_7828 {
  strings:
    $key_7828 = { 2f 5a [2] 1d 78 [2] 1b 4d [2] 35 4d [2] 0a 51 }

  condition:
    any of them
}