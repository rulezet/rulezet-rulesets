rule TTP_XOR_WriteProcessMemory_1b31 {
  strings:
    $key_1b31 = { 4c 43 [2] 7e 61 [2] 78 54 [2] 56 54 [2] 69 48 }

  condition:
    any of them
}