rule TTP_XOR_WriteProcessMemory_efc8 {
  strings:
    $key_efc8 = { b8 ba [2] 8a 98 [2] 8c ad [2] a2 ad [2] 9d b1 }

  condition:
    any of them
}