rule TTP_XOR_WriteProcessMemory_c07b {
  strings:
    $key_c07b = { 97 09 [2] a5 2b [2] a3 1e [2] 8d 1e [2] b2 02 }

  condition:
    any of them
}