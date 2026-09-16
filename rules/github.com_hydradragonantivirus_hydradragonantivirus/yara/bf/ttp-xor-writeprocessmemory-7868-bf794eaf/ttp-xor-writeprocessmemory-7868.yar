rule TTP_XOR_WriteProcessMemory_7868 {
  strings:
    $key_7868 = { 2f 1a [2] 1d 38 [2] 1b 0d [2] 35 0d [2] 0a 11 }

  condition:
    any of them
}