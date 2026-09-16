rule TTP_XOR_WriteProcessMemory_acdc {
  strings:
    $key_acdc = { fb ae [2] c9 8c [2] cf b9 [2] e1 b9 [2] de a5 }

  condition:
    any of them
}