rule TTP_XOR_WriteProcessMemory_aca2 {
  strings:
    $key_aca2 = { fb d0 [2] c9 f2 [2] cf c7 [2] e1 c7 [2] de db }

  condition:
    any of them
}