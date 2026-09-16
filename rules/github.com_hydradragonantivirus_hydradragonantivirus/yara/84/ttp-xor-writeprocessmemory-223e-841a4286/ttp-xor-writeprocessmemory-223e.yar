rule TTP_XOR_WriteProcessMemory_223e {
  strings:
    $key_223e = { 75 4c [2] 47 6e [2] 41 5b [2] 6f 5b [2] 50 47 }

  condition:
    any of them
}