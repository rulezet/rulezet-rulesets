rule TTP_XOR_WriteProcessMemory_b78e {
  strings:
    $key_b78e = { e0 fc [2] d2 de [2] d4 eb [2] fa eb [2] c5 f7 }

  condition:
    any of them
}