rule TTP_XOR_WriteProcessMemory_7961 {
  strings:
    $key_7961 = { 2e 13 [2] 1c 31 [2] 1a 04 [2] 34 04 [2] 0b 18 }

  condition:
    any of them
}