rule TTP_XOR_WriteProcessMemory_209a {
  strings:
    $key_209a = { 77 e8 [2] 45 ca [2] 43 ff [2] 6d ff [2] 52 e3 }

  condition:
    any of them
}