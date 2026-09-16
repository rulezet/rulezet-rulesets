rule TTP_XOR_WriteProcessMemory_ade3 {
  strings:
    $key_ade3 = { fa 91 [2] c8 b3 [2] ce 86 [2] e0 86 [2] df 9a }

  condition:
    any of them
}