rule TTP_XOR_WriteProcessMemory_03d7 {
  strings:
    $key_03d7 = { 54 a5 [2] 66 87 [2] 60 b2 [2] 4e b2 [2] 71 ae }

  condition:
    any of them
}