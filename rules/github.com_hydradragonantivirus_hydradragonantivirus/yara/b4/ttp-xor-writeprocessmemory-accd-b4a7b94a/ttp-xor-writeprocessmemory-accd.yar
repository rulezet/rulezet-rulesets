rule TTP_XOR_WriteProcessMemory_accd {
  strings:
    $key_accd = { fb bf [2] c9 9d [2] cf a8 [2] e1 a8 [2] de b4 }

  condition:
    any of them
}