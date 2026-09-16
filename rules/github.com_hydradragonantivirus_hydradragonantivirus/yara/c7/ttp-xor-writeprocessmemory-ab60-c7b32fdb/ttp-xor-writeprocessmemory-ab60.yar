rule TTP_XOR_WriteProcessMemory_ab60 {
  strings:
    $key_ab60 = { fc 12 [2] ce 30 [2] c8 05 [2] e6 05 [2] d9 19 }

  condition:
    any of them
}