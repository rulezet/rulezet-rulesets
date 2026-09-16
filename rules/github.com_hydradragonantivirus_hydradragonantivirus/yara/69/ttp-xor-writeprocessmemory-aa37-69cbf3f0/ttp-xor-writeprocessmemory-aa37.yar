rule TTP_XOR_WriteProcessMemory_aa37 {
  strings:
    $key_aa37 = { fd 45 [2] cf 67 [2] c9 52 [2] e7 52 [2] d8 4e }

  condition:
    any of them
}