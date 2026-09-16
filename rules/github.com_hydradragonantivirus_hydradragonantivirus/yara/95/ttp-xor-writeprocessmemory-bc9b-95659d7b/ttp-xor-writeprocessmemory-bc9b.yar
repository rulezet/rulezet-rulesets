rule TTP_XOR_WriteProcessMemory_bc9b {
  strings:
    $key_bc9b = { eb e9 [2] d9 cb [2] df fe [2] f1 fe [2] ce e2 }

  condition:
    any of them
}