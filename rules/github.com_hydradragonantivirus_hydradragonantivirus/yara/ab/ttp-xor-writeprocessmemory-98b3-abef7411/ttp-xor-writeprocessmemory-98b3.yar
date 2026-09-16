rule TTP_XOR_WriteProcessMemory_98b3 {
  strings:
    $key_98b3 = { cf c1 [2] fd e3 [2] fb d6 [2] d5 d6 [2] ea ca }

  condition:
    any of them
}