rule TTP_XOR_WriteProcessMemory_bd61 {
  strings:
    $key_bd61 = { ea 13 [2] d8 31 [2] de 04 [2] f0 04 [2] cf 18 }

  condition:
    any of them
}