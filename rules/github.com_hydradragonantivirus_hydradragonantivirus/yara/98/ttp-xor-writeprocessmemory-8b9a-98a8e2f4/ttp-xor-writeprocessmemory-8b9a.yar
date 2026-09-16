rule TTP_XOR_WriteProcessMemory_8b9a {
  strings:
    $key_8b9a = { dc e8 [2] ee ca [2] e8 ff [2] c6 ff [2] f9 e3 }

  condition:
    any of them
}