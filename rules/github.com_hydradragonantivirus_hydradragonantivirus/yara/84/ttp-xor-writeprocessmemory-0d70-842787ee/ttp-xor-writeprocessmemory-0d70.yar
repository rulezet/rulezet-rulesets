rule TTP_XOR_WriteProcessMemory_0d70 {
  strings:
    $key_0d70 = { 5a 02 [2] 68 20 [2] 6e 15 [2] 40 15 [2] 7f 09 }

  condition:
    any of them
}