rule TTP_XOR_WriteProcessMemory_5ad7 {
  strings:
    $key_5ad7 = { 0d a5 [2] 3f 87 [2] 39 b2 [2] 17 b2 [2] 28 ae }

  condition:
    any of them
}