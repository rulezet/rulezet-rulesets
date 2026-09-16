rule TTP_XOR_WriteProcessMemory_2ecc {
  strings:
    $key_2ecc = { 79 be [2] 4b 9c [2] 4d a9 [2] 63 a9 [2] 5c b5 }

  condition:
    any of them
}