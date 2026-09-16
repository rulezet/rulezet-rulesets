rule TTP_XOR_WriteProcessMemory_ab75 {
  strings:
    $key_ab75 = { fc 07 [2] ce 25 [2] c8 10 [2] e6 10 [2] d9 0c }

  condition:
    any of them
}