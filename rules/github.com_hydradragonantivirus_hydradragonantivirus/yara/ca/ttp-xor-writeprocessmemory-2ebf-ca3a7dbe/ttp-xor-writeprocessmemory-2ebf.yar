rule TTP_XOR_WriteProcessMemory_2ebf {
  strings:
    $key_2ebf = { 79 cd [2] 4b ef [2] 4d da [2] 63 da [2] 5c c6 }

  condition:
    any of them
}