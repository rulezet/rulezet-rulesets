rule TTP_XOR_WriteProcessMemory_488a {
  strings:
    $key_488a = { 1f f8 [2] 2d da [2] 2b ef [2] 05 ef [2] 3a f3 }

  condition:
    any of them
}