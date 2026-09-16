rule TTP_XOR_WriteProcessMemory_748f {
  strings:
    $key_748f = { 23 fd [2] 11 df [2] 17 ea [2] 39 ea [2] 06 f6 }

  condition:
    any of them
}