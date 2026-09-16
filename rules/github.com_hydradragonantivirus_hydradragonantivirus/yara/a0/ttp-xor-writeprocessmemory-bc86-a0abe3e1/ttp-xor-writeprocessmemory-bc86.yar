rule TTP_XOR_WriteProcessMemory_bc86 {
  strings:
    $key_bc86 = { eb f4 [2] d9 d6 [2] df e3 [2] f1 e3 [2] ce ff }

  condition:
    any of them
}