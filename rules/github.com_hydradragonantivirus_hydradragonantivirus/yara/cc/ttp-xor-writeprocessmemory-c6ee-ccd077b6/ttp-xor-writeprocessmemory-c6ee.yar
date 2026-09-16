rule TTP_XOR_WriteProcessMemory_c6ee {
  strings:
    $key_c6ee = { 91 9c [2] a3 be [2] a5 8b [2] 8b 8b [2] b4 97 }

  condition:
    any of them
}