rule TTP_XOR_WriteProcessMemory_98b2 {
  strings:
    $key_98b2 = { cf c0 [2] fd e2 [2] fb d7 [2] d5 d7 [2] ea cb }

  condition:
    any of them
}