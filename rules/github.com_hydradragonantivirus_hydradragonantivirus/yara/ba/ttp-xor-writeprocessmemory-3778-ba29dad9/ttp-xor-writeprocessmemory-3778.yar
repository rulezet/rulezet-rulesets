rule TTP_XOR_WriteProcessMemory_3778 {
  strings:
    $key_3778 = { 60 0a [2] 52 28 [2] 54 1d [2] 7a 1d [2] 45 01 }

  condition:
    any of them
}