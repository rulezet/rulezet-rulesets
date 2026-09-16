rule TTP_XOR_WriteProcessMemory_6978 {
  strings:
    $key_6978 = { 3e 0a [2] 0c 28 [2] 0a 1d [2] 24 1d [2] 1b 01 }

  condition:
    any of them
}