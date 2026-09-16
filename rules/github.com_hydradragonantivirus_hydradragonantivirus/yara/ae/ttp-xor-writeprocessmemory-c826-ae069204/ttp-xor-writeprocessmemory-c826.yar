rule TTP_XOR_WriteProcessMemory_c826 {
  strings:
    $key_c826 = { 9f 54 [2] ad 76 [2] ab 43 [2] 85 43 [2] ba 5f }

  condition:
    any of them
}