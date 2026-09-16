rule TTP_XOR_WriteProcessMemory_0942 {
  strings:
    $key_0942 = { 5e 30 [2] 6c 12 [2] 6a 27 [2] 44 27 [2] 7b 3b }

  condition:
    any of them
}