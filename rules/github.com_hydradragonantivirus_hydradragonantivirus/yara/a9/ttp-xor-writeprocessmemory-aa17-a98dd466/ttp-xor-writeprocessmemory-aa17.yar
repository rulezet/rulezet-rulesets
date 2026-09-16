rule TTP_XOR_WriteProcessMemory_aa17 {
  strings:
    $key_aa17 = { fd 65 [2] cf 47 [2] c9 72 [2] e7 72 [2] d8 6e }

  condition:
    any of them
}