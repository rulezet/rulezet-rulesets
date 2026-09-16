rule TTP_XOR_WriteProcessMemory_4578 {
  strings:
    $key_4578 = { 12 0a [2] 20 28 [2] 26 1d [2] 08 1d [2] 37 01 }

  condition:
    any of them
}