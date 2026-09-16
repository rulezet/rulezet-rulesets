rule TTP_XOR_WriteProcessMemory_32c8 {
  strings:
    $key_32c8 = { 65 ba [2] 57 98 [2] 51 ad [2] 7f ad [2] 40 b1 }

  condition:
    any of them
}