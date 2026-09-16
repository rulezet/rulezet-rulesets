rule TTP_XOR_WriteProcessMemory_028a {
  strings:
    $key_028a = { 55 f8 [2] 67 da [2] 61 ef [2] 4f ef [2] 70 f3 }

  condition:
    any of them
}