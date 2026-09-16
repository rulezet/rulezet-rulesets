rule TTP_XOR_WriteProcessMemory_2478 {
  strings:
    $key_2478 = { 73 0a [2] 41 28 [2] 47 1d [2] 69 1d [2] 56 01 }

  condition:
    any of them
}