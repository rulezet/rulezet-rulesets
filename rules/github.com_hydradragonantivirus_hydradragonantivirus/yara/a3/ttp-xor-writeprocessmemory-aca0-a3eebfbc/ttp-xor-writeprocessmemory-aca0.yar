rule TTP_XOR_WriteProcessMemory_aca0 {
  strings:
    $key_aca0 = { fb d2 [2] c9 f0 [2] cf c5 [2] e1 c5 [2] de d9 }

  condition:
    any of them
}