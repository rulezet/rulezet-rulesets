rule TTP_XOR_WriteProcessMemory_7ded {
  strings:
    $key_7ded = { 2a 9f [2] 18 bd [2] 1e 88 [2] 30 88 [2] 0f 94 }

  condition:
    any of them
}