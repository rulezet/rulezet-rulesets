rule TTP_XOR_WriteProcessMemory_3ad7 {
  strings:
    $key_3ad7 = { 6d a5 [2] 5f 87 [2] 59 b2 [2] 77 b2 [2] 48 ae }

  condition:
    any of them
}