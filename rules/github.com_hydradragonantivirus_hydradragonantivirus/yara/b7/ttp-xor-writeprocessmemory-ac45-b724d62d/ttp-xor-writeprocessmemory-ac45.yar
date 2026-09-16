rule TTP_XOR_WriteProcessMemory_ac45 {
  strings:
    $key_ac45 = { fb 37 [2] c9 15 [2] cf 20 [2] e1 20 [2] de 3c }

  condition:
    any of them
}