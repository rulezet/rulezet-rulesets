rule TTP_XOR_WriteProcessMemory_0368 {
  strings:
    $key_0368 = { 54 1a [2] 66 38 [2] 60 0d [2] 4e 0d [2] 71 11 }

  condition:
    any of them
}