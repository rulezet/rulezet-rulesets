rule TTP_XOR_WriteProcessMemory_7d68 {
  strings:
    $key_7d68 = { 2a 1a [2] 18 38 [2] 1e 0d [2] 30 0d [2] 0f 11 }

  condition:
    any of them
}