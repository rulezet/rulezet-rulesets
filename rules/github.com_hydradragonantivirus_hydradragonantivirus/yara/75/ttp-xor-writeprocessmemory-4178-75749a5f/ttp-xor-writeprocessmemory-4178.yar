rule TTP_XOR_WriteProcessMemory_4178 {
  strings:
    $key_4178 = { 16 0a [2] 24 28 [2] 22 1d [2] 0c 1d [2] 33 01 }

  condition:
    any of them
}