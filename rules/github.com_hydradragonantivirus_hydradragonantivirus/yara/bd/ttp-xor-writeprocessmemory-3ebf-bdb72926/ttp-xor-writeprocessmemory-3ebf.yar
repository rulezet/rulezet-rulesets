rule TTP_XOR_WriteProcessMemory_3ebf {
  strings:
    $key_3ebf = { 69 cd [2] 5b ef [2] 5d da [2] 73 da [2] 4c c6 }

  condition:
    any of them
}