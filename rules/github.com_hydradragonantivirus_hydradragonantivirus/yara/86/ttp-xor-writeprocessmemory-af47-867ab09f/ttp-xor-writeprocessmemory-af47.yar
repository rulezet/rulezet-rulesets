rule TTP_XOR_WriteProcessMemory_af47 {
  strings:
    $key_af47 = { f8 35 [2] ca 17 [2] cc 22 [2] e2 22 [2] dd 3e }

  condition:
    any of them
}