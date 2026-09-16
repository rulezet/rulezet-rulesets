rule TTP_XOR_WriteProcessMemory_ff8a {
  strings:
    $key_ff8a = { a8 f8 [2] 9a da [2] 9c ef [2] b2 ef [2] 8d f3 }

  condition:
    any of them
}