rule TTP_XOR_WriteProcessMemory_eaa9 {
  strings:
    $key_eaa9 = { bd db [2] 8f f9 [2] 89 cc [2] a7 cc [2] 98 d0 }

  condition:
    any of them
}