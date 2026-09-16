rule TTP_XOR_WriteProcessMemory_c876 {
  strings:
    $key_c876 = { 9f 04 [2] ad 26 [2] ab 13 [2] 85 13 [2] ba 0f }

  condition:
    any of them
}