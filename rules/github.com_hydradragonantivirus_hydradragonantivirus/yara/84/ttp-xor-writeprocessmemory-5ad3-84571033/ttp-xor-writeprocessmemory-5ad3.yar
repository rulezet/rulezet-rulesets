rule TTP_XOR_WriteProcessMemory_5ad3 {
  strings:
    $key_5ad3 = { 0d a1 [2] 3f 83 [2] 39 b6 [2] 17 b6 [2] 28 aa }

  condition:
    any of them
}