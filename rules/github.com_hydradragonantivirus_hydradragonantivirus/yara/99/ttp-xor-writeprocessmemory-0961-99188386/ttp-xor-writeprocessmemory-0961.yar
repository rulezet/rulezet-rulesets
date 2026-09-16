rule TTP_XOR_WriteProcessMemory_0961 {
  strings:
    $key_0961 = { 5e 13 [2] 6c 31 [2] 6a 04 [2] 44 04 [2] 7b 18 }

  condition:
    any of them
}