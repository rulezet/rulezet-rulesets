rule TTP_XOR_WriteProcessMemory_2b8a {
  strings:
    $key_2b8a = { 7c f8 [2] 4e da [2] 48 ef [2] 66 ef [2] 59 f3 }

  condition:
    any of them
}