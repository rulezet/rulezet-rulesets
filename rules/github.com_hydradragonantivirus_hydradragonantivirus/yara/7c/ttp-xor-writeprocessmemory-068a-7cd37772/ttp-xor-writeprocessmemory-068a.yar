rule TTP_XOR_WriteProcessMemory_068a {
  strings:
    $key_068a = { 51 f8 [2] 63 da [2] 65 ef [2] 4b ef [2] 74 f3 }

  condition:
    any of them
}