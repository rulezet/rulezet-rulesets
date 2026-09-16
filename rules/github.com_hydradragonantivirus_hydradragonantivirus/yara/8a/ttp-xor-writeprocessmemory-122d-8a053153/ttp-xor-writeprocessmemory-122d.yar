rule TTP_XOR_WriteProcessMemory_122d {
  strings:
    $key_122d = { 45 5f [2] 77 7d [2] 71 48 [2] 5f 48 [2] 60 54 }

  condition:
    any of them
}