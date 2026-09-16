rule TTP_XOR_WriteProcessMemory_82ba {
  strings:
    $key_82ba = { d5 c8 [2] e7 ea [2] e1 df [2] cf df [2] f0 c3 }

  condition:
    any of them
}