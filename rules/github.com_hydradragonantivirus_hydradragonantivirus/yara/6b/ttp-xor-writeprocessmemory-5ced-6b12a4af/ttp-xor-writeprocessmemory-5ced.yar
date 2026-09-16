rule TTP_XOR_WriteProcessMemory_5ced {
  strings:
    $key_5ced = { 0b 9f [2] 39 bd [2] 3f 88 [2] 11 88 [2] 2e 94 }

  condition:
    any of them
}