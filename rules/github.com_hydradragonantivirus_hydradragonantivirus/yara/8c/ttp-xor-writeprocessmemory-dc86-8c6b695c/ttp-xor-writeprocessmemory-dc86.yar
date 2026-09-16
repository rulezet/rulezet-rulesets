rule TTP_XOR_WriteProcessMemory_dc86 {
  strings:
    $key_dc86 = { 8b f4 [2] b9 d6 [2] bf e3 [2] 91 e3 [2] ae ff }

  condition:
    any of them
}