rule TTP_XOR_WriteProcessMemory_e88a {
  strings:
    $key_e88a = { bf f8 [2] 8d da [2] 8b ef [2] a5 ef [2] 9a f3 }

  condition:
    any of them
}