rule TTP_XOR_WriteProcessMemory_c38e {
  strings:
    $key_c38e = { 94 fc [2] a6 de [2] a0 eb [2] 8e eb [2] b1 f7 }

  condition:
    any of them
}