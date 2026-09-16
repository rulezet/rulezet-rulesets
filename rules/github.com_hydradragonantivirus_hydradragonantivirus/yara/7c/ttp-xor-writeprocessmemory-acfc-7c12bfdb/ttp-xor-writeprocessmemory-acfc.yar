rule TTP_XOR_WriteProcessMemory_acfc {
  strings:
    $key_acfc = { fb 8e [2] c9 ac [2] cf 99 [2] e1 99 [2] de 85 }

  condition:
    any of them
}