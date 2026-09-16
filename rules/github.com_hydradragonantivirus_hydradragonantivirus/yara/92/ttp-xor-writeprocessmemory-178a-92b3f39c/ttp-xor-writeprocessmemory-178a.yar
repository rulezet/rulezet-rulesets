rule TTP_XOR_WriteProcessMemory_178a {
  strings:
    $key_178a = { 40 f8 [2] 72 da [2] 74 ef [2] 5a ef [2] 65 f3 }

  condition:
    any of them
}