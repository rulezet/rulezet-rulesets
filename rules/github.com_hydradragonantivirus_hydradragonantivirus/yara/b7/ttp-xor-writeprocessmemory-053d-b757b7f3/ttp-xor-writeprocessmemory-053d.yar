rule TTP_XOR_WriteProcessMemory_053d {
  strings:
    $key_053d = { 52 4f [2] 60 6d [2] 66 58 [2] 48 58 [2] 77 44 }

  condition:
    any of them
}