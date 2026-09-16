rule TTP_XOR_WriteProcessMemory_188a {
  strings:
    $key_188a = { 4f f8 [2] 7d da [2] 7b ef [2] 55 ef [2] 6a f3 }

  condition:
    any of them
}