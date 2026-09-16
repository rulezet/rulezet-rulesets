rule TTP_XOR_WriteProcessMemory_468a {
  strings:
    $key_468a = { 11 f8 [2] 23 da [2] 25 ef [2] 0b ef [2] 34 f3 }

  condition:
    any of them
}