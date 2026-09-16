rule TTP_XOR_WriteProcessMemory_cfc2 {
  strings:
    $key_cfc2 = { 98 b0 [2] aa 92 [2] ac a7 [2] 82 a7 [2] bd bb }

  condition:
    any of them
}