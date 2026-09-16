rule TTP_XOR_WriteProcessMemory_c017 {
  strings:
    $key_c017 = { 97 65 [2] a5 47 [2] a3 72 [2] 8d 72 [2] b2 6e }

  condition:
    any of them
}