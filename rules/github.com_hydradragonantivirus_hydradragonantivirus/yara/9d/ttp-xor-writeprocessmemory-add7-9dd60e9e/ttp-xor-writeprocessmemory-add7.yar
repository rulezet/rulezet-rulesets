rule TTP_XOR_WriteProcessMemory_add7 {
  strings:
    $key_add7 = { fa a5 [2] c8 87 [2] ce b2 [2] e0 b2 [2] df ae }

  condition:
    any of them
}