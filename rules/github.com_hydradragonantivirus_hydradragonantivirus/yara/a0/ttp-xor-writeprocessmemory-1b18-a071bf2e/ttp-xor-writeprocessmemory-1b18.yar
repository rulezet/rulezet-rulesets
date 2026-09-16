rule TTP_XOR_WriteProcessMemory_1b18 {
  strings:
    $key_1b18 = { 4c 6a [2] 7e 48 [2] 78 7d [2] 56 7d [2] 69 61 }

  condition:
    any of them
}