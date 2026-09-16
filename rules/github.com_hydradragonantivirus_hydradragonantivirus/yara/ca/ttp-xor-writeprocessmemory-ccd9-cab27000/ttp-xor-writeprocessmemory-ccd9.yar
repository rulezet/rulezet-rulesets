rule TTP_XOR_WriteProcessMemory_ccd9 {
  strings:
    $key_ccd9 = { 9b ab [2] a9 89 [2] af bc [2] 81 bc [2] be a0 }

  condition:
    any of them
}