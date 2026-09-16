rule TTP_XOR_WriteProcessMemory_aa15 {
  strings:
    $key_aa15 = { fd 67 [2] cf 45 [2] c9 70 [2] e7 70 [2] d8 6c }

  condition:
    any of them
}