rule TTP_XOR_WriteProcessMemory_3894 {
  strings:
    $key_3894 = { 6f e6 [2] 5d c4 [2] 5b f1 [2] 75 f1 [2] 4a ed }

  condition:
    any of them
}