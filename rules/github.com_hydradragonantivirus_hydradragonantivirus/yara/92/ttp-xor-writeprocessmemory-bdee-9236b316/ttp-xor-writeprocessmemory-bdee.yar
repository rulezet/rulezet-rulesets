rule TTP_XOR_WriteProcessMemory_bdee {
  strings:
    $key_bdee = { ea 9c [2] d8 be [2] de 8b [2] f0 8b [2] cf 97 }

  condition:
    any of them
}