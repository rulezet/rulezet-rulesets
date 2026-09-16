rule TTP_XOR_WriteProcessMemory_3952 {
  strings:
    $key_3952 = { 6e 20 [2] 5c 02 [2] 5a 37 [2] 74 37 [2] 4b 2b }

  condition:
    any of them
}