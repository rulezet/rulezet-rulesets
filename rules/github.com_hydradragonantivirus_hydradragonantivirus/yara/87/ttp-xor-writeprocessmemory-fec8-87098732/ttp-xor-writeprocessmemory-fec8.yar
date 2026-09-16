rule TTP_XOR_WriteProcessMemory_fec8 {
  strings:
    $key_fec8 = { a9 ba [2] 9b 98 [2] 9d ad [2] b3 ad [2] 8c b1 }

  condition:
    any of them
}