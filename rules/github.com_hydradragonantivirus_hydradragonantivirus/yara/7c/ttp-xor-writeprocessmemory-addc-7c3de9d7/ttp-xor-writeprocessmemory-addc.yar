rule TTP_XOR_WriteProcessMemory_addc {
  strings:
    $key_addc = { fa ae [2] c8 8c [2] ce b9 [2] e0 b9 [2] df a5 }

  condition:
    any of them
}