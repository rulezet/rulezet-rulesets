rule TTP_XOR_WriteProcessMemory_5638 {
  strings:
    $key_5638 = { 01 4a [2] 33 68 [2] 35 5d [2] 1b 5d [2] 24 41 }

  condition:
    any of them
}