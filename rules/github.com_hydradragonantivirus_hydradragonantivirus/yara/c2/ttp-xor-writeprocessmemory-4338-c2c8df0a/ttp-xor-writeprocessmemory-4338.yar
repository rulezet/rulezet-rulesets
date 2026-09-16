rule TTP_XOR_WriteProcessMemory_4338 {
  strings:
    $key_4338 = { 14 4a [2] 26 68 [2] 20 5d [2] 0e 5d [2] 31 41 }

  condition:
    any of them
}