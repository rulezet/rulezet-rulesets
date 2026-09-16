rule TTP_XOR_WriteProcessMemory_eba8 {
  strings:
    $key_eba8 = { bc da [2] 8e f8 [2] 88 cd [2] a6 cd [2] 99 d1 }

  condition:
    any of them
}