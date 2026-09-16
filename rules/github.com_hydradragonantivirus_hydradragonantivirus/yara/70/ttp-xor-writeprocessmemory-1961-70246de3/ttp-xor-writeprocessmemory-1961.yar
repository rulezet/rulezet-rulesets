rule TTP_XOR_WriteProcessMemory_1961 {
  strings:
    $key_1961 = { 4e 13 [2] 7c 31 [2] 7a 04 [2] 54 04 [2] 6b 18 }

  condition:
    any of them
}