rule TTP_XOR_WriteProcessMemory_1778 {
  strings:
    $key_1778 = { 40 0a [2] 72 28 [2] 74 1d [2] 5a 1d [2] 65 01 }

  condition:
    any of them
}