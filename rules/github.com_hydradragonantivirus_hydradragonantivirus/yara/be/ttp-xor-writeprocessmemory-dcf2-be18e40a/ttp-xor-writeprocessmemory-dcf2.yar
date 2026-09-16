rule TTP_XOR_WriteProcessMemory_dcf2 {
  strings:
    $key_dcf2 = { 8b 80 [2] b9 a2 [2] bf 97 [2] 91 97 [2] ae 8b }

  condition:
    any of them
}