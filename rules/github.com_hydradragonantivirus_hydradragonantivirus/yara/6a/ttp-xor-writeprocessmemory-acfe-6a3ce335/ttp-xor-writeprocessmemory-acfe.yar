rule TTP_XOR_WriteProcessMemory_acfe {
  strings:
    $key_acfe = { fb 8c [2] c9 ae [2] cf 9b [2] e1 9b [2] de 87 }

  condition:
    any of them
}