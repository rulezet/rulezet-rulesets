rule TTP_XOR_WriteProcessMemory_05d7 {
  strings:
    $key_05d7 = { 52 a5 [2] 60 87 [2] 66 b2 [2] 48 b2 [2] 77 ae }

  condition:
    any of them
}