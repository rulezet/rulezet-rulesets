rule TTP_XOR_WriteProcessMemory_adf3 {
  strings:
    $key_adf3 = { fa 81 [2] c8 a3 [2] ce 96 [2] e0 96 [2] df 8a }

  condition:
    any of them
}