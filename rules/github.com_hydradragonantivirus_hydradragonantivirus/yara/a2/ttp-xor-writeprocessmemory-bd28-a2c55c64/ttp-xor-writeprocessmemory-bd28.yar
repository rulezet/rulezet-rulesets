rule TTP_XOR_WriteProcessMemory_bd28 {
  strings:
    $key_bd28 = { ea 5a [2] d8 78 [2] de 4d [2] f0 4d [2] cf 51 }

  condition:
    any of them
}