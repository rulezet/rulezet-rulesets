rule TTP_XOR_WriteProcessMemory_ec22 {
  strings:
    $key_ec22 = { bb 50 [2] 89 72 [2] 8f 47 [2] a1 47 [2] 9e 5b }

  condition:
    any of them
}