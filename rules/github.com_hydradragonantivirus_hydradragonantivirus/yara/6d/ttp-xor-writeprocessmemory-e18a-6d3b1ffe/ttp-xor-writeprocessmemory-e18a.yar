rule TTP_XOR_WriteProcessMemory_e18a {
  strings:
    $key_e18a = { b6 f8 [2] 84 da [2] 82 ef [2] ac ef [2] 93 f3 }

  condition:
    any of them
}