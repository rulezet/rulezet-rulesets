rule TTP_XOR_WriteProcessMemory_7ced {
  strings:
    $key_7ced = { 2b 9f [2] 19 bd [2] 1f 88 [2] 31 88 [2] 0e 94 }

  condition:
    any of them
}