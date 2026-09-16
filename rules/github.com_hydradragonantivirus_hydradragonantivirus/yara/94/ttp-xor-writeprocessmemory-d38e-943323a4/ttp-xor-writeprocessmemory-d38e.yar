rule TTP_XOR_WriteProcessMemory_d38e {
  strings:
    $key_d38e = { 84 fc [2] b6 de [2] b0 eb [2] 9e eb [2] a1 f7 }

  condition:
    any of them
}