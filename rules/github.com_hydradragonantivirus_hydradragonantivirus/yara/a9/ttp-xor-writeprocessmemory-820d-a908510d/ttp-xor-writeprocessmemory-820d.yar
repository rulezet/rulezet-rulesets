rule TTP_XOR_WriteProcessMemory_820d {
  strings:
    $key_820d = { d5 7f [2] e7 5d [2] e1 68 [2] cf 68 [2] f0 74 }

  condition:
    any of them
}