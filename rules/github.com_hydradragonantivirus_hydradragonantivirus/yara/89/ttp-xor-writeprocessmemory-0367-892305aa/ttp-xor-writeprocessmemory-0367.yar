rule TTP_XOR_WriteProcessMemory_0367 {
  strings:
    $key_0367 = { 54 15 [2] 66 37 [2] 60 02 [2] 4e 02 [2] 71 1e }

  condition:
    any of them
}