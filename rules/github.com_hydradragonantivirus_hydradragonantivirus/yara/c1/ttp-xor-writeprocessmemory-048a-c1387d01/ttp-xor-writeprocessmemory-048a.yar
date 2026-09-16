rule TTP_XOR_WriteProcessMemory_048a {
  strings:
    $key_048a = { 53 f8 [2] 61 da [2] 67 ef [2] 49 ef [2] 76 f3 }

  condition:
    any of them
}