rule TTP_XOR_WriteProcessMemory_bd08 {
  strings:
    $key_bd08 = { ea 7a [2] d8 58 [2] de 6d [2] f0 6d [2] cf 71 }

  condition:
    any of them
}