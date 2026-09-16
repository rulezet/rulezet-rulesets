rule TTP_XOR_WriteProcessMemory_bd38 {
  strings:
    $key_bd38 = { ea 4a [2] d8 68 [2] de 5d [2] f0 5d [2] cf 41 }

  condition:
    any of them
}