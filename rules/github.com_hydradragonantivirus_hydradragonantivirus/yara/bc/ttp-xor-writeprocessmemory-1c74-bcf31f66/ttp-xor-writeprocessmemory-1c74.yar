rule TTP_XOR_WriteProcessMemory_1c74 {
  strings:
    $key_1c74 = { 4b 06 [2] 79 24 [2] 7f 11 [2] 51 11 [2] 6e 0d }

  condition:
    any of them
}