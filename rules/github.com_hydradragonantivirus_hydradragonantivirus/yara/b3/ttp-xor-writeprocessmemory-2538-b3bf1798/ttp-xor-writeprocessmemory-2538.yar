rule TTP_XOR_WriteProcessMemory_2538 {
  strings:
    $key_2538 = { 72 4a [2] 40 68 [2] 46 5d [2] 68 5d [2] 57 41 }

  condition:
    any of them
}