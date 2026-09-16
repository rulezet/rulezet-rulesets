rule TTP_XOR_WriteProcessMemory_c62c {
  strings:
    $key_c62c = { 91 5e [2] a3 7c [2] a5 49 [2] 8b 49 [2] b4 55 }

  condition:
    any of them
}