rule TTP_XOR_WriteProcessMemory_11e3 {
  strings:
    $key_11e3 = { 46 91 [2] 74 b3 [2] 72 86 [2] 5c 86 [2] 63 9a }

  condition:
    any of them
}