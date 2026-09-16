rule TTP_XOR_WriteProcessMemory_142d {
  strings:
    $key_142d = { 43 5f [2] 71 7d [2] 77 48 [2] 59 48 [2] 66 54 }

  condition:
    any of them
}