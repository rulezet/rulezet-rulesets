rule TTP_XOR_WriteProcessMemory_add6 {
  strings:
    $key_add6 = { fa a4 [2] c8 86 [2] ce b3 [2] e0 b3 [2] df af }

  condition:
    any of them
}