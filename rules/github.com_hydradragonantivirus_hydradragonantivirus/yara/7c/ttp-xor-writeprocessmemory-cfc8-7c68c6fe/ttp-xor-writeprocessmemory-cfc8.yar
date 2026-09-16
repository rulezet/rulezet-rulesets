rule TTP_XOR_WriteProcessMemory_cfc8 {
  strings:
    $key_cfc8 = { 98 ba [2] aa 98 [2] ac ad [2] 82 ad [2] bd b1 }

  condition:
    any of them
}