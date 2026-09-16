rule TTP_XOR_WriteProcessMemory_c887 {
  strings:
    $key_c887 = { 9f f5 [2] ad d7 [2] ab e2 [2] 85 e2 [2] ba fe }

  condition:
    any of them
}