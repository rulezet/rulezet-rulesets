rule TTP_XOR_WriteProcessMemory_8787 {
  strings:
    $key_8787 = { d0 f5 [2] e2 d7 [2] e4 e2 [2] ca e2 [2] f5 fe }

  condition:
    any of them
}