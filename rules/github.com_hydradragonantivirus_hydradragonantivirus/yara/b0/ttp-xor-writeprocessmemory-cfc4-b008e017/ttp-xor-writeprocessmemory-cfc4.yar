rule TTP_XOR_WriteProcessMemory_cfc4 {
  strings:
    $key_cfc4 = { 98 b6 [2] aa 94 [2] ac a1 [2] 82 a1 [2] bd bd }

  condition:
    any of them
}