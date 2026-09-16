rule TTP_XOR_WriteProcessMemory_bd93 {
  strings:
    $key_bd93 = { ea e1 [2] d8 c3 [2] de f6 [2] f0 f6 [2] cf ea }

  condition:
    any of them
}