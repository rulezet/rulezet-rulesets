rule TTP_XOR_WriteProcessMemory_7ecc {
  strings:
    $key_7ecc = { 29 be [2] 1b 9c [2] 1d a9 [2] 33 a9 [2] 0c b5 }

  condition:
    any of them
}