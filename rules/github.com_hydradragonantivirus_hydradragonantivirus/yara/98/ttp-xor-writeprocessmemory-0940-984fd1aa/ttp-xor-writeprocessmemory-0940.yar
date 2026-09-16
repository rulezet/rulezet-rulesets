rule TTP_XOR_WriteProcessMemory_0940 {
  strings:
    $key_0940 = { 5e 32 [2] 6c 10 [2] 6a 25 [2] 44 25 [2] 7b 39 }

  condition:
    any of them
}