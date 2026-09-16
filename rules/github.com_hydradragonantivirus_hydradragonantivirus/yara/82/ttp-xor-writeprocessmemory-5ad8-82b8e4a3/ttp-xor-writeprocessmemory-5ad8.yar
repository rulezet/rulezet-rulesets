rule TTP_XOR_WriteProcessMemory_5ad8 {
  strings:
    $key_5ad8 = { 0d aa [2] 3f 88 [2] 39 bd [2] 17 bd [2] 28 a1 }

  condition:
    any of them
}