rule TTP_XOR_WriteProcessMemory_823c {
  strings:
    $key_823c = { d5 4e [2] e7 6c [2] e1 59 [2] cf 59 [2] f0 45 }

  condition:
    any of them
}