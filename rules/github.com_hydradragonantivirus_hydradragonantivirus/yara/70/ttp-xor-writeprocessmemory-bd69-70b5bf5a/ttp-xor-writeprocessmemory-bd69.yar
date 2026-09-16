rule TTP_XOR_WriteProcessMemory_bd69 {
  strings:
    $key_bd69 = { ea 1b [2] d8 39 [2] de 0c [2] f0 0c [2] cf 10 }

  condition:
    any of them
}