rule TTP_XOR_WriteProcessMemory_498a {
  strings:
    $key_498a = { 1e f8 [2] 2c da [2] 2a ef [2] 04 ef [2] 3b f3 }

  condition:
    any of them
}