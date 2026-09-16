rule TTP_XOR_WriteProcessMemory_351e {
  strings:
    $key_351e = { 62 6c [2] 50 4e [2] 56 7b [2] 78 7b [2] 47 67 }

  condition:
    any of them
}