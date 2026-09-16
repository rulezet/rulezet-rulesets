rule TTP_XOR_WriteProcessMemory_058a {
  strings:
    $key_058a = { 52 f8 [2] 60 da [2] 66 ef [2] 48 ef [2] 77 f3 }

  condition:
    any of them
}