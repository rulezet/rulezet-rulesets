rule TTP_XOR_WriteProcessMemory_4b13 {
  strings:
    $key_4b13 = { 1c 61 [2] 2e 43 [2] 28 76 [2] 06 76 [2] 39 6a }

  condition:
    any of them
}