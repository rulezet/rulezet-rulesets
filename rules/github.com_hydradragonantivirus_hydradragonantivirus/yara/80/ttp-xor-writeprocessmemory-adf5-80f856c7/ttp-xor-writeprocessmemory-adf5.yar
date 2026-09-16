rule TTP_XOR_WriteProcessMemory_adf5 {
  strings:
    $key_adf5 = { fa 87 [2] c8 a5 [2] ce 90 [2] e0 90 [2] df 8c }

  condition:
    any of them
}