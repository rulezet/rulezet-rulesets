rule TTP_XOR_WriteProcessMemory_6d18 {
  strings:
    $key_6d18 = { 3a 6a [2] 08 48 [2] 0e 7d [2] 20 7d [2] 1f 61 }

  condition:
    any of them
}