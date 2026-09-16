rule TTP_XOR_WriteProcessMemory_0970 {
  strings:
    $key_0970 = { 5e 02 [2] 6c 20 [2] 6a 15 [2] 44 15 [2] 7b 09 }

  condition:
    any of them
}