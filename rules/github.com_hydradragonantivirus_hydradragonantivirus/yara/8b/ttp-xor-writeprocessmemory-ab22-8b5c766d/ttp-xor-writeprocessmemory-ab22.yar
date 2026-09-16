rule TTP_XOR_WriteProcessMemory_ab22 {
  strings:
    $key_ab22 = { fc 50 [2] ce 72 [2] c8 47 [2] e6 47 [2] d9 5b }

  condition:
    any of them
}