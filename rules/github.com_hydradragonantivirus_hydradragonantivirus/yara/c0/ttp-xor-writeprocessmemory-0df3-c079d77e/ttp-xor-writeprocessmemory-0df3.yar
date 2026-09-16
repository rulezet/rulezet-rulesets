rule TTP_XOR_WriteProcessMemory_0df3 {
  strings:
    $key_0df3 = { 5a 81 [2] 68 a3 [2] 6e 96 [2] 40 96 [2] 7f 8a }

  condition:
    any of them
}