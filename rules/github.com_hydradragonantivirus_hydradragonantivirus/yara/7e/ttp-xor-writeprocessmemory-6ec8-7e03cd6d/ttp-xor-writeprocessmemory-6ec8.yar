rule TTP_XOR_WriteProcessMemory_6ec8 {
  strings:
    $key_6ec8 = { 39 ba [2] 0b 98 [2] 0d ad [2] 23 ad [2] 1c b1 }

  condition:
    any of them
}