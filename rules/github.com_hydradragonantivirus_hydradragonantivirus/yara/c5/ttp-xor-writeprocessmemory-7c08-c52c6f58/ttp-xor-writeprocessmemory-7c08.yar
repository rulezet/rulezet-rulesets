rule TTP_XOR_WriteProcessMemory_7c08 {
  strings:
    $key_7c08 = { 2b 7a [2] 19 58 [2] 1f 6d [2] 31 6d [2] 0e 71 }

  condition:
    any of them
}