rule TTP_XOR_WriteProcessMemory_99c4 {
  strings:
    $key_99c4 = { ce b6 [2] fc 94 [2] fa a1 [2] d4 a1 [2] eb bd }

  condition:
    any of them
}