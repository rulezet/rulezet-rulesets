rule TTP_XOR_WriteProcessMemory_4ec8 {
  strings:
    $key_4ec8 = { 19 ba [2] 2b 98 [2] 2d ad [2] 03 ad [2] 3c b1 }

  condition:
    any of them
}