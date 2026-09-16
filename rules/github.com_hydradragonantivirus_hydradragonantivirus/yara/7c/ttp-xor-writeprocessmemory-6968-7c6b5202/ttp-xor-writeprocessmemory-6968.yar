rule TTP_XOR_WriteProcessMemory_6968 {
  strings:
    $key_6968 = { 3e 1a [2] 0c 38 [2] 0a 0d [2] 24 0d [2] 1b 11 }

  condition:
    any of them
}