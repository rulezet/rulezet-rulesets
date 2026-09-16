rule TTP_XOR_WriteProcessMemory_ab20 {
  strings:
    $key_ab20 = { fc 52 [2] ce 70 [2] c8 45 [2] e6 45 [2] d9 59 }

  condition:
    any of them
}