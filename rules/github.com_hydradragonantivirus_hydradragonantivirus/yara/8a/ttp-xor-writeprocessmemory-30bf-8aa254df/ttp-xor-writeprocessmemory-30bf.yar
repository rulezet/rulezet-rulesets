rule TTP_XOR_WriteProcessMemory_30bf {
  strings:
    $key_30bf = { 67 cd [2] 55 ef [2] 53 da [2] 7d da [2] 42 c6 }

  condition:
    any of them
}