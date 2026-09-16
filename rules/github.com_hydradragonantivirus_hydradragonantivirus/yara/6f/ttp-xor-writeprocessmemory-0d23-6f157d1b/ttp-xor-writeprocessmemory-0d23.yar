rule TTP_XOR_WriteProcessMemory_0d23 {
  strings:
    $key_0d23 = { 5a 51 [2] 68 73 [2] 6e 46 [2] 40 46 [2] 7f 5a }

  condition:
    any of them
}