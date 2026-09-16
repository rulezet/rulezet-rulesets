rule TTP_XOR_WriteProcessMemory_5518 {
  strings:
    $key_5518 = { 02 6a [2] 30 48 [2] 36 7d [2] 18 7d [2] 27 61 }

  condition:
    any of them
}