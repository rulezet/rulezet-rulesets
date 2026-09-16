rule TTP_XOR_WriteProcessMemory_7bc8 {
  strings:
    $key_7bc8 = { 2c ba [2] 1e 98 [2] 18 ad [2] 36 ad [2] 09 b1 }

  condition:
    any of them
}