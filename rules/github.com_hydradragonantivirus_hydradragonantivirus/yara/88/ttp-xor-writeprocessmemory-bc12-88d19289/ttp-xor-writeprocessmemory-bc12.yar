rule TTP_XOR_WriteProcessMemory_bc12 {
  strings:
    $key_bc12 = { eb 60 [2] d9 42 [2] df 77 [2] f1 77 [2] ce 6b }

  condition:
    any of them
}