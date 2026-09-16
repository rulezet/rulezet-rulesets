rule TTP_XOR_WriteProcessMemory_eba9 {
  strings:
    $key_eba9 = { bc db [2] 8e f9 [2] 88 cc [2] a6 cc [2] 99 d0 }

  condition:
    any of them
}