rule TTP_XOR_WriteProcessMemory_2b78 {
  strings:
    $key_2b78 = { 7c 0a [2] 4e 28 [2] 48 1d [2] 66 1d [2] 59 01 }

  condition:
    any of them
}