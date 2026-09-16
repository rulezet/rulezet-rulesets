rule TTP_XOR_WriteProcessMemory_af57 {
  strings:
    $key_af57 = { f8 25 [2] ca 07 [2] cc 32 [2] e2 32 [2] dd 2e }

  condition:
    any of them
}