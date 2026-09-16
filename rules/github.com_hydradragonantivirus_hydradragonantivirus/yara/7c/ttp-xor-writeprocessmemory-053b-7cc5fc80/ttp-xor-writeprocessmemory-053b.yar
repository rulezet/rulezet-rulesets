rule TTP_XOR_WriteProcessMemory_053b {
  strings:
    $key_053b = { 52 49 [2] 60 6b [2] 66 5e [2] 48 5e [2] 77 42 }

  condition:
    any of them
}