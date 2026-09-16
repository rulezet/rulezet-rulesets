rule TTP_XOR_WriteProcessMemory_0468 {
  strings:
    $key_0468 = { 53 1a [2] 61 38 [2] 67 0d [2] 49 0d [2] 76 11 }

  condition:
    any of them
}