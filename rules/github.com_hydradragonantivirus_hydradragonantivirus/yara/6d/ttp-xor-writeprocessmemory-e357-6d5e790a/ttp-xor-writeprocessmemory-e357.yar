rule TTP_XOR_WriteProcessMemory_e357 {
  strings:
    $key_e357 = { b4 25 [2] 86 07 [2] 80 32 [2] ae 32 [2] 91 2e }

  condition:
    any of them
}