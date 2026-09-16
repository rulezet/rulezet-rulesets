rule TTP_XOR_WriteProcessMemory_d48e {
  strings:
    $key_d48e = { 83 fc [2] b1 de [2] b7 eb [2] 99 eb [2] a6 f7 }

  condition:
    any of them
}