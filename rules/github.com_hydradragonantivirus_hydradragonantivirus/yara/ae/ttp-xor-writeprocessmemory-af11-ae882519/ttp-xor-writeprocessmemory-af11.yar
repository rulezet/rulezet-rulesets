rule TTP_XOR_WriteProcessMemory_af11 {
  strings:
    $key_af11 = { f8 63 [2] ca 41 [2] cc 74 [2] e2 74 [2] dd 68 }

  condition:
    any of them
}