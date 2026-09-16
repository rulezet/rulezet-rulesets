rule TTP_XOR_WriteProcessMemory_7278 {
  strings:
    $key_7278 = { 25 0a [2] 17 28 [2] 11 1d [2] 3f 1d [2] 00 01 }

  condition:
    any of them
}