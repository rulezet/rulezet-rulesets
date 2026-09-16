rule TTP_XOR_WriteProcessMemory_e68a {
  strings:
    $key_e68a = { b1 f8 [2] 83 da [2] 85 ef [2] ab ef [2] 94 f3 }

  condition:
    any of them
}