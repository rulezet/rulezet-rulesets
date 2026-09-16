rule TTP_XOR_WriteProcessMemory_8186 {
  strings:
    $key_8186 = { d6 f4 [2] e4 d6 [2] e2 e3 [2] cc e3 [2] f3 ff }

  condition:
    any of them
}