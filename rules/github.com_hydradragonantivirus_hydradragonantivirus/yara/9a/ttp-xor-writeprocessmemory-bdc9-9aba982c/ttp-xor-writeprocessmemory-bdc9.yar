rule TTP_XOR_WriteProcessMemory_bdc9 {
  strings:
    $key_bdc9 = { ea bb [2] d8 99 [2] de ac [2] f0 ac [2] cf b0 }

  condition:
    any of them
}