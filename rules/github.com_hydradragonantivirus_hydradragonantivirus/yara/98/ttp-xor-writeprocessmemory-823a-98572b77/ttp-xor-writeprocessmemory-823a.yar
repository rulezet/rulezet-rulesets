rule TTP_XOR_WriteProcessMemory_823a {
  strings:
    $key_823a = { d5 48 [2] e7 6a [2] e1 5f [2] cf 5f [2] f0 43 }

  condition:
    any of them
}