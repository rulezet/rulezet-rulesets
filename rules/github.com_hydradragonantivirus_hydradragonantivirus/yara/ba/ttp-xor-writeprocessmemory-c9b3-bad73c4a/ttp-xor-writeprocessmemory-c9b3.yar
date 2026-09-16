rule TTP_XOR_WriteProcessMemory_c9b3 {
  strings:
    $key_c9b3 = { 9e c1 [2] ac e3 [2] aa d6 [2] 84 d6 [2] bb ca }

  condition:
    any of them
}