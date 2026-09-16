rule TTP_XOR_WriteProcessMemory_99a8 {
  strings:
    $key_99a8 = { ce da [2] fc f8 [2] fa cd [2] d4 cd [2] eb d1 }

  condition:
    any of them
}