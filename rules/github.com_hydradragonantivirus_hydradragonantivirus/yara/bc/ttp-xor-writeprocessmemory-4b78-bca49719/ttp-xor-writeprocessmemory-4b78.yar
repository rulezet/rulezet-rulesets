rule TTP_XOR_WriteProcessMemory_4b78 {
  strings:
    $key_4b78 = { 1c 0a [2] 2e 28 [2] 28 1d [2] 06 1d [2] 39 01 }

  condition:
    any of them
}