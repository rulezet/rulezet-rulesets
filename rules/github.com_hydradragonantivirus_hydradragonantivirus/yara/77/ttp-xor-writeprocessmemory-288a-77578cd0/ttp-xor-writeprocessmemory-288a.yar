rule TTP_XOR_WriteProcessMemory_288a {
  strings:
    $key_288a = { 7f f8 [2] 4d da [2] 4b ef [2] 65 ef [2] 5a f3 }

  condition:
    any of them
}