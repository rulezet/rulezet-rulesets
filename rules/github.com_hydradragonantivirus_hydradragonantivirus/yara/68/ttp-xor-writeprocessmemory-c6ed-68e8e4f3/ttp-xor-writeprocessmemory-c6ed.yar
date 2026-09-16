rule TTP_XOR_WriteProcessMemory_c6ed {
  strings:
    $key_c6ed = { 91 9f [2] a3 bd [2] a5 88 [2] 8b 88 [2] b4 94 }

  condition:
    any of them
}