rule TTP_XOR_WriteProcessMemory_acfd {
  strings:
    $key_acfd = { fb 8f [2] c9 ad [2] cf 98 [2] e1 98 [2] de 84 }

  condition:
    any of them
}