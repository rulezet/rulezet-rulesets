rule TTP_XOR_WriteProcessMemory_8786 {
  strings:
    $key_8786 = { d0 f4 [2] e2 d6 [2] e4 e3 [2] ca e3 [2] f5 ff }

  condition:
    any of them
}