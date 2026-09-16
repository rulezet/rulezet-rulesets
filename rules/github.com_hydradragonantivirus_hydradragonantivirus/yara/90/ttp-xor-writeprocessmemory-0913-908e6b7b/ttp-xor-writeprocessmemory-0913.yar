rule TTP_XOR_WriteProcessMemory_0913 {
  strings:
    $key_0913 = { 5e 61 [2] 6c 43 [2] 6a 76 [2] 44 76 [2] 7b 6a }

  condition:
    any of them
}