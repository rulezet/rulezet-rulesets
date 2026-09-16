rule TTP_XOR_WriteProcessMemory_2278 {
  strings:
    $key_2278 = { 75 0a [2] 47 28 [2] 41 1d [2] 6f 1d [2] 50 01 }

  condition:
    any of them
}