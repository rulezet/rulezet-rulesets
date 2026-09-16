rule TTP_XOR_WriteProcessMemory_acfb {
  strings:
    $key_acfb = { fb 89 [2] c9 ab [2] cf 9e [2] e1 9e [2] de 82 }

  condition:
    any of them
}