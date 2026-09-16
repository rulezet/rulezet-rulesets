rule TTP_XOR_WriteProcessMemory_af24 {
  strings:
    $key_af24 = { f8 56 [2] ca 74 [2] cc 41 [2] e2 41 [2] dd 5d }

  condition:
    any of them
}