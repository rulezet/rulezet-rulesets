rule TTP_XOR_WriteProcessMemory_0c23 {
  strings:
    $key_0c23 = { 5b 51 [2] 69 73 [2] 6f 46 [2] 41 46 [2] 7e 5a }

  condition:
    any of them
}