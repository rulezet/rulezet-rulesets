rule TTP_XOR_WriteProcessMemory_1fc8 {
  strings:
    $key_1fc8 = { 48 ba [2] 7a 98 [2] 7c ad [2] 52 ad [2] 6d b1 }

  condition:
    any of them
}