rule TTP_XOR_WriteProcessMemory_af01 {
  strings:
    $key_af01 = { f8 73 [2] ca 51 [2] cc 64 [2] e2 64 [2] dd 78 }

  condition:
    any of them
}