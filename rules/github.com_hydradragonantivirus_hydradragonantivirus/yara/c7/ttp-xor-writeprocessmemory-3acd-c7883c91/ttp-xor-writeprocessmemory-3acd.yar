rule TTP_XOR_WriteProcessMemory_3acd {
  strings:
    $key_3acd = { 6d bf [2] 5f 9d [2] 59 a8 [2] 77 a8 [2] 48 b4 }

  condition:
    any of them
}