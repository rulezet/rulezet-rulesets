rule TTP_XOR_WriteProcessMemory_dc80 {
  strings:
    $key_dc80 = { 8b f2 [2] b9 d0 [2] bf e5 [2] 91 e5 [2] ae f9 }

  condition:
    any of them
}