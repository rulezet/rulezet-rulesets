rule TTP_XOR_WriteProcessMemory_5d74 {
  strings:
    $key_5d74 = { 0a 06 [2] 38 24 [2] 3e 11 [2] 10 11 [2] 2f 0d }

  condition:
    any of them
}