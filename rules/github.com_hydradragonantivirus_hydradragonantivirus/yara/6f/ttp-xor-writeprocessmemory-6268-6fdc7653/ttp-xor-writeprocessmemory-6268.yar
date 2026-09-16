rule TTP_XOR_WriteProcessMemory_6268 {
  strings:
    $key_6268 = { 35 1a [2] 07 38 [2] 01 0d [2] 2f 0d [2] 10 11 }

  condition:
    any of them
}