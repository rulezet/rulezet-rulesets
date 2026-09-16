rule TTP_XOR_WriteProcessMemory_05ec {
  strings:
    $key_05ec = { 52 9e [2] 60 bc [2] 66 89 [2] 48 89 [2] 77 95 }

  condition:
    any of them
}