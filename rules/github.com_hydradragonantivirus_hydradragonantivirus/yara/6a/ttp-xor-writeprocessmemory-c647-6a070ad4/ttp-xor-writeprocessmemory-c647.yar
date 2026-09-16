rule TTP_XOR_WriteProcessMemory_c647 {
  strings:
    $key_c647 = { 91 35 [2] a3 17 [2] a5 22 [2] 8b 22 [2] b4 3e }

  condition:
    any of them
}