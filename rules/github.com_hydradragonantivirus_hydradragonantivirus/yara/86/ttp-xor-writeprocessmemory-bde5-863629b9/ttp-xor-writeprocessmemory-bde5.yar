rule TTP_XOR_WriteProcessMemory_bde5 {
  strings:
    $key_bde5 = { ea 97 [2] d8 b5 [2] de 80 [2] f0 80 [2] cf 9c }

  condition:
    any of them
}