rule TTP_XOR_WriteProcessMemory_af34 {
  strings:
    $key_af34 = { f8 46 [2] ca 64 [2] cc 51 [2] e2 51 [2] dd 4d }

  condition:
    any of them
}