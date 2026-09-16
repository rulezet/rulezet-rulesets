rule TTP_XOR_WriteProcessMemory_afa9 {
  strings:
    $key_afa9 = { f8 db [2] ca f9 [2] cc cc [2] e2 cc [2] dd d0 }

  condition:
    any of them
}