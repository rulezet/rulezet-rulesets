rule TTP_XOR_WriteProcessMemory_0bc8 {
  strings:
    $key_0bc8 = { 5c ba [2] 6e 98 [2] 68 ad [2] 46 ad [2] 79 b1 }

  condition:
    any of them
}