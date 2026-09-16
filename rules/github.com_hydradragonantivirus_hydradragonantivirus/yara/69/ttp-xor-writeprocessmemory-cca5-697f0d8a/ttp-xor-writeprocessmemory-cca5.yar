rule TTP_XOR_WriteProcessMemory_cca5 {
  strings:
    $key_cca5 = { 9b d7 [2] a9 f5 [2] af c0 [2] 81 c0 [2] be dc }

  condition:
    any of them
}