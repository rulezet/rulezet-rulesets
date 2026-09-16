rule TTP_XOR_WriteProcessMemory_ace9 {
  strings:
    $key_ace9 = { fb 9b [2] c9 b9 [2] cf 8c [2] e1 8c [2] de 90 }

  condition:
    any of them
}