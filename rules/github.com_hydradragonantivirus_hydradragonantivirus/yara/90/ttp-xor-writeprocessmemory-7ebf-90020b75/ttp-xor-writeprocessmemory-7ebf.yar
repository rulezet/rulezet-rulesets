rule TTP_XOR_WriteProcessMemory_7ebf {
  strings:
    $key_7ebf = { 29 cd [2] 1b ef [2] 1d da [2] 33 da [2] 0c c6 }

  condition:
    any of them
}