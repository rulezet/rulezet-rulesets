rule TTP_XOR_WriteProcessMemory_c693 {
  strings:
    $key_c693 = { 91 e1 [2] a3 c3 [2] a5 f6 [2] 8b f6 [2] b4 ea }

  condition:
    any of them
}