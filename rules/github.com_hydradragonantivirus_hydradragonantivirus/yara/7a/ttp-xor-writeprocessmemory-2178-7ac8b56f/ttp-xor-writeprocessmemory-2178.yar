rule TTP_XOR_WriteProcessMemory_2178 {
  strings:
    $key_2178 = { 76 0a [2] 44 28 [2] 42 1d [2] 6c 1d [2] 53 01 }

  condition:
    any of them
}