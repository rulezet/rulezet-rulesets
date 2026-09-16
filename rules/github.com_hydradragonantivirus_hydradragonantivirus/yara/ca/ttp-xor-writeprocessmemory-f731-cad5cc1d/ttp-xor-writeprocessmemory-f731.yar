rule TTP_XOR_WriteProcessMemory_f731 {
  strings:
    $key_f731 = { a0 43 [2] 92 61 [2] 94 54 [2] ba 54 [2] 85 48 }

  condition:
    any of them
}