rule TTP_XOR_WriteProcessMemory_c622 {
  strings:
    $key_c622 = { 91 50 [2] a3 72 [2] a5 47 [2] 8b 47 [2] b4 5b }

  condition:
    any of them
}