rule TTP_XOR_WriteProcessMemory_d0d7 {
  strings:
    $key_d0d7 = { 87 a5 [2] b5 87 [2] b3 b2 [2] 9d b2 [2] a2 ae }

  condition:
    any of them
}