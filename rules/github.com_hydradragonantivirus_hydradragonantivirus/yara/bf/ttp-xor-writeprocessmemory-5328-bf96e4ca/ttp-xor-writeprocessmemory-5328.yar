rule TTP_XOR_WriteProcessMemory_5328 {
  strings:
    $key_5328 = { 04 5a [2] 36 78 [2] 30 4d [2] 1e 4d [2] 21 51 }

  condition:
    any of them
}