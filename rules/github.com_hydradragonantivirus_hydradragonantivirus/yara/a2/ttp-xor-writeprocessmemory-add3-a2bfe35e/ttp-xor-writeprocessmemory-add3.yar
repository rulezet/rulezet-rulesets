rule TTP_XOR_WriteProcessMemory_add3 {
  strings:
    $key_add3 = { fa a1 [2] c8 83 [2] ce b6 [2] e0 b6 [2] df aa }

  condition:
    any of them
}