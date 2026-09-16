rule TTP_XOR_WriteProcessMemory_7fc8 {
  strings:
    $key_7fc8 = { 28 ba [2] 1a 98 [2] 1c ad [2] 32 ad [2] 0d b1 }

  condition:
    any of them
}