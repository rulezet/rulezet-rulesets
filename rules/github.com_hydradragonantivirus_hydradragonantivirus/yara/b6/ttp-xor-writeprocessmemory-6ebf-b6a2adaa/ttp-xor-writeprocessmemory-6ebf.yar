rule TTP_XOR_WriteProcessMemory_6ebf {
  strings:
    $key_6ebf = { 39 cd [2] 0b ef [2] 0d da [2] 23 da [2] 1c c6 }

  condition:
    any of them
}