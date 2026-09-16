rule TTP_XOR_WriteProcessMemory_bd35 {
  strings:
    $key_bd35 = { ea 47 [2] d8 65 [2] de 50 [2] f0 50 [2] cf 4c }

  condition:
    any of them
}