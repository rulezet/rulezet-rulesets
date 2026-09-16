rule TTP_XOR_WriteProcessMemory_5ad5 {
  strings:
    $key_5ad5 = { 0d a7 [2] 3f 85 [2] 39 b0 [2] 17 b0 [2] 28 ac }

  condition:
    any of them
}