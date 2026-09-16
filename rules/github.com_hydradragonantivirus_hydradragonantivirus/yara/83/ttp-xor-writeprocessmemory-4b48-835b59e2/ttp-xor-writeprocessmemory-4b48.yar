rule TTP_XOR_WriteProcessMemory_4b48 {
  strings:
    $key_4b48 = { 1c 3a [2] 2e 18 [2] 28 2d [2] 06 2d [2] 39 31 }

  condition:
    any of them
}