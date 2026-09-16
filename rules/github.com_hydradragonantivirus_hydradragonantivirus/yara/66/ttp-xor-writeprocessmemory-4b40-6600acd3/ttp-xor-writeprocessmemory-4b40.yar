rule TTP_XOR_WriteProcessMemory_4b40 {
  strings:
    $key_4b40 = { 1c 32 [2] 2e 10 [2] 28 25 [2] 06 25 [2] 39 39 }

  condition:
    any of them
}