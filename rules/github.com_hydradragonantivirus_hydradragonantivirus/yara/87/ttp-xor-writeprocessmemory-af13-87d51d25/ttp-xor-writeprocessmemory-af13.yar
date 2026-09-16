rule TTP_XOR_WriteProcessMemory_af13 {
  strings:
    $key_af13 = { f8 61 [2] ca 43 [2] cc 76 [2] e2 76 [2] dd 6a }

  condition:
    any of them
}