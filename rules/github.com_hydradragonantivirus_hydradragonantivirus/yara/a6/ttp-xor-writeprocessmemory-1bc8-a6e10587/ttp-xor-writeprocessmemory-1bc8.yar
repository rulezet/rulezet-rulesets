rule TTP_XOR_WriteProcessMemory_1bc8 {
  strings:
    $key_1bc8 = { 4c ba [2] 7e 98 [2] 78 ad [2] 56 ad [2] 69 b1 }

  condition:
    any of them
}