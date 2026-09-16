rule TTP_XOR_WriteProcessMemory_acce {
  strings:
    $key_acce = { fb bc [2] c9 9e [2] cf ab [2] e1 ab [2] de b7 }

  condition:
    any of them
}