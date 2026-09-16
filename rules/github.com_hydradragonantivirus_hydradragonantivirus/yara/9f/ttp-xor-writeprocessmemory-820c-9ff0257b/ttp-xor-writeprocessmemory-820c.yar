rule TTP_XOR_WriteProcessMemory_820c {
  strings:
    $key_820c = { d5 7e [2] e7 5c [2] e1 69 [2] cf 69 [2] f0 75 }

  condition:
    any of them
}