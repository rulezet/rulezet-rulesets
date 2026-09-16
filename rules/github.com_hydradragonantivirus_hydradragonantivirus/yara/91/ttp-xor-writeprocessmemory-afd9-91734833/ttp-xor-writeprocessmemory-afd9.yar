rule TTP_XOR_WriteProcessMemory_afd9 {
  strings:
    $key_afd9 = { f8 ab [2] ca 89 [2] cc bc [2] e2 bc [2] dd a0 }

  condition:
    any of them
}