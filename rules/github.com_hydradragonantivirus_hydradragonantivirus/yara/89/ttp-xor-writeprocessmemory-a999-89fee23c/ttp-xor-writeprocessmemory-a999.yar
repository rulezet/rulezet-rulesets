rule TTP_XOR_WriteProcessMemory_a999 {
  strings:
    $key_a999 = { fe eb [2] cc c9 [2] ca fc [2] e4 fc [2] db e0 }

  condition:
    any of them
}