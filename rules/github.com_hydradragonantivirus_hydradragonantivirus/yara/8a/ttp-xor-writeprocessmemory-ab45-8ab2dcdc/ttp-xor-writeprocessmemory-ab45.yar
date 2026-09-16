rule TTP_XOR_WriteProcessMemory_ab45 {
  strings:
    $key_ab45 = { fc 37 [2] ce 15 [2] c8 20 [2] e6 20 [2] d9 3c }

  condition:
    any of them
}