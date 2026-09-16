rule TTP_XOR_WriteProcessMemory_4bc8 {
  strings:
    $key_4bc8 = { 1c ba [2] 2e 98 [2] 28 ad [2] 06 ad [2] 39 b1 }

  condition:
    any of them
}