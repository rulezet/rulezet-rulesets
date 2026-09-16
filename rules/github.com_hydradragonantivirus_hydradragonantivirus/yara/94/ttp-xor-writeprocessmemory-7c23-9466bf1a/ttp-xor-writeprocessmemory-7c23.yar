rule TTP_XOR_WriteProcessMemory_7c23 {
  strings:
    $key_7c23 = { 2b 51 [2] 19 73 [2] 1f 46 [2] 31 46 [2] 0e 5a }

  condition:
    any of them
}