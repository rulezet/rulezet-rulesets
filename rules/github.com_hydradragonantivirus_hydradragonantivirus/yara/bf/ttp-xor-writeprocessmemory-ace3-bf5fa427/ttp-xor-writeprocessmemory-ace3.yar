rule TTP_XOR_WriteProcessMemory_ace3 {
  strings:
    $key_ace3 = { fb 91 [2] c9 b3 [2] cf 86 [2] e1 86 [2] de 9a }

  condition:
    any of them
}