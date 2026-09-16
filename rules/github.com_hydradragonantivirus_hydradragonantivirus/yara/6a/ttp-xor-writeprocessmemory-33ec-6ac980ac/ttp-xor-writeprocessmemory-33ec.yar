rule TTP_XOR_WriteProcessMemory_33ec {
  strings:
    $key_33ec = { 64 9e [2] 56 bc [2] 50 89 [2] 7e 89 [2] 41 95 }

  condition:
    any of them
}