rule TTP_XOR_WriteProcessMemory_0d61 {
  strings:
    $key_0d61 = { 5a 13 [2] 68 31 [2] 6e 04 [2] 40 04 [2] 7f 18 }

  condition:
    any of them
}