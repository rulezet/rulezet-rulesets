rule TTP_XOR_WriteProcessMemory_7d48 {
  strings:
    $key_7d48 = { 2a 3a [2] 18 18 [2] 1e 2d [2] 30 2d [2] 0f 31 }

  condition:
    any of them
}