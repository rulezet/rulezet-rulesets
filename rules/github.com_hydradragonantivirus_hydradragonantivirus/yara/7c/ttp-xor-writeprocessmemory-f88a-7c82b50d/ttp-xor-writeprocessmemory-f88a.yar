rule TTP_XOR_WriteProcessMemory_f88a {
  strings:
    $key_f88a = { af f8 [2] 9d da [2] 9b ef [2] b5 ef [2] 8a f3 }

  condition:
    any of them
}