rule TTP_XOR_WriteProcessMemory_c619 {
  strings:
    $key_c619 = { 91 6b [2] a3 49 [2] a5 7c [2] 8b 7c [2] b4 60 }

  condition:
    any of them
}