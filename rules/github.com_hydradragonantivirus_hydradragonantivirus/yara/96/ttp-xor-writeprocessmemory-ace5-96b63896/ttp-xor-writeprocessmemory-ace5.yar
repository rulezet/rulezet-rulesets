rule TTP_XOR_WriteProcessMemory_ace5 {
  strings:
    $key_ace5 = { fb 97 [2] c9 b5 [2] cf 80 [2] e1 80 [2] de 9c }

  condition:
    any of them
}