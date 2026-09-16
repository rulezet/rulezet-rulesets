rule TTP_XOR_WriteProcessMemory_aceb {
  strings:
    $key_aceb = { fb 99 [2] c9 bb [2] cf 8e [2] e1 8e [2] de 92 }

  condition:
    any of them
}