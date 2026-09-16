rule TTP_XOR_WriteProcessMemory_bd15 {
  strings:
    $key_bd15 = { ea 67 [2] d8 45 [2] de 70 [2] f0 70 [2] cf 6c }

  condition:
    any of them
}