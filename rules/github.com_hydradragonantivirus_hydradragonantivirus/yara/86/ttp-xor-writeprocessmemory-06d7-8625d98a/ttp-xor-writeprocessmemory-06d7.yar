rule TTP_XOR_WriteProcessMemory_06d7 {
  strings:
    $key_06d7 = { 51 a5 [2] 63 87 [2] 65 b2 [2] 4b b2 [2] 74 ae }

  condition:
    any of them
}