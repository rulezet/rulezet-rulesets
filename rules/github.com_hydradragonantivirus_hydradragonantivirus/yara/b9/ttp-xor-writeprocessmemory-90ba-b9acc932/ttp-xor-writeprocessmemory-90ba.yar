rule TTP_XOR_WriteProcessMemory_90ba {
  strings:
    $key_90ba = { c7 c8 [2] f5 ea [2] f3 df [2] dd df [2] e2 c3 }

  condition:
    any of them
}