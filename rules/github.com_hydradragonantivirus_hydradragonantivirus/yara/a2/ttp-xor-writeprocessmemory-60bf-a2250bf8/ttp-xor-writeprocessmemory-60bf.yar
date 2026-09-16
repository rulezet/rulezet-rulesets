rule TTP_XOR_WriteProcessMemory_60bf {
  strings:
    $key_60bf = { 37 cd [2] 05 ef [2] 03 da [2] 2d da [2] 12 c6 }

  condition:
    any of them
}