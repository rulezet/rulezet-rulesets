rule TTP_XOR_WriteProcessMemory_adf4 {
  strings:
    $key_adf4 = { fa 86 [2] c8 a4 [2] ce 91 [2] e0 91 [2] df 8d }

  condition:
    any of them
}