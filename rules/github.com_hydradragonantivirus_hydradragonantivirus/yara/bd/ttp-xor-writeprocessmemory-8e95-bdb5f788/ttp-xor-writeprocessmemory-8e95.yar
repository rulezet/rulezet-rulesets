rule TTP_XOR_WriteProcessMemory_8e95 {
  strings:
    $key_8e95 = { d9 e7 [2] eb c5 [2] ed f0 [2] c3 f0 [2] fc ec }

  condition:
    any of them
}