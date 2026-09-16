rule TTP_XOR_WriteProcessMemory_d88a {
  strings:
    $key_d88a = { 8f f8 [2] bd da [2] bb ef [2] 95 ef [2] aa f3 }

  condition:
    any of them
}