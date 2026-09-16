rule TTP_XOR_WriteProcessMemory_2bd7 {
  strings:
    $key_2bd7 = { 7c a5 [2] 4e 87 [2] 48 b2 [2] 66 b2 [2] 59 ae }

  condition:
    any of them
}