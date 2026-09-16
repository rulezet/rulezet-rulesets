rule TTP_XOR_WriteProcessMemory_add2 {
  strings:
    $key_add2 = { fa a0 [2] c8 82 [2] ce b7 [2] e0 b7 [2] df ab }

  condition:
    any of them
}