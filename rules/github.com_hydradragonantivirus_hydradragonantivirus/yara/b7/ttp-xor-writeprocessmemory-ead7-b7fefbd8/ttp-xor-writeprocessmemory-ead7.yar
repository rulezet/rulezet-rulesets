rule TTP_XOR_WriteProcessMemory_ead7 {
  strings:
    $key_ead7 = { bd a5 [2] 8f 87 [2] 89 b2 [2] a7 b2 [2] 98 ae }

  condition:
    any of them
}