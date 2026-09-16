rule TTP_XOR_WriteProcessMemory_364e {
  strings:
    $key_364e = { 61 3c [2] 53 1e [2] 55 2b [2] 7b 2b [2] 44 37 }

  condition:
    any of them
}