rule TTP_XOR_WriteProcessMemory_af10 {
  strings:
    $key_af10 = { f8 62 [2] ca 40 [2] cc 75 [2] e2 75 [2] dd 69 }

  condition:
    any of them
}