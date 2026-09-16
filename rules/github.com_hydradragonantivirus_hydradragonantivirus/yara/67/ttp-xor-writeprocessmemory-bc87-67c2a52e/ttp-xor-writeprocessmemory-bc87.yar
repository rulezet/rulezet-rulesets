rule TTP_XOR_WriteProcessMemory_bc87 {
  strings:
    $key_bc87 = { eb f5 [2] d9 d7 [2] df e2 [2] f1 e2 [2] ce fe }

  condition:
    any of them
}