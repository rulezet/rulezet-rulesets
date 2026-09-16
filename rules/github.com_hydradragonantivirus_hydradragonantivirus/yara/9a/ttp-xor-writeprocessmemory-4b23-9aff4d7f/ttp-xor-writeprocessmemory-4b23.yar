rule TTP_XOR_WriteProcessMemory_4b23 {
  strings:
    $key_4b23 = { 1c 51 [2] 2e 73 [2] 28 46 [2] 06 46 [2] 39 5a }

  condition:
    any of them
}