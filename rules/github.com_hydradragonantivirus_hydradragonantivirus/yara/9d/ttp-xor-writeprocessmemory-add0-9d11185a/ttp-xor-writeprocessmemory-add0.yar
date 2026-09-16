rule TTP_XOR_WriteProcessMemory_add0 {
  strings:
    $key_add0 = { fa a2 [2] c8 80 [2] ce b5 [2] e0 b5 [2] df a9 }

  condition:
    any of them
}