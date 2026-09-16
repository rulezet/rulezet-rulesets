rule TTP_XOR_WriteProcessMemory_abd5 {
  strings:
    $key_abd5 = { fc a7 [2] ce 85 [2] c8 b0 [2] e6 b0 [2] d9 ac }

  condition:
    any of them
}