rule TTP_XOR_WriteProcessMemory_ab35 {
  strings:
    $key_ab35 = { fc 47 [2] ce 65 [2] c8 50 [2] e6 50 [2] d9 4c }

  condition:
    any of them
}