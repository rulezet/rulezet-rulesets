rule TTP_XOR_WriteProcessMemory_1c52 {
  strings:
    $key_1c52 = { 4b 20 [2] 79 02 [2] 7f 37 [2] 51 37 [2] 6e 2b }

  condition:
    any of them
}