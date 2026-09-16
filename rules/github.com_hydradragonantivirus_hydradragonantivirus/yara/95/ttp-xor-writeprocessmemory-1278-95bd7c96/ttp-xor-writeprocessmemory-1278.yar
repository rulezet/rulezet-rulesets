rule TTP_XOR_WriteProcessMemory_1278 {
  strings:
    $key_1278 = { 45 0a [2] 77 28 [2] 71 1d [2] 5f 1d [2] 60 01 }

  condition:
    any of them
}