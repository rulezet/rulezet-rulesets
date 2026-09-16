rule TTP_XOR_WriteProcessMemory_823f {
  strings:
    $key_823f = { d5 4d [2] e7 6f [2] e1 5a [2] cf 5a [2] f0 46 }

  condition:
    any of them
}