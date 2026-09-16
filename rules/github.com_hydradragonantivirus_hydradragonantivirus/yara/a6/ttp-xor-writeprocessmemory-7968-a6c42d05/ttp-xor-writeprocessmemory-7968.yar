rule TTP_XOR_WriteProcessMemory_7968 {
  strings:
    $key_7968 = { 2e 1a [2] 1c 38 [2] 1a 0d [2] 34 0d [2] 0b 11 }

  condition:
    any of them
}