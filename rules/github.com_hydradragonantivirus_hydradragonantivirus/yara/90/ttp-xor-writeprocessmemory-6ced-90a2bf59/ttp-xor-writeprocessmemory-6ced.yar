rule TTP_XOR_WriteProcessMemory_6ced {
  strings:
    $key_6ced = { 3b 9f [2] 09 bd [2] 0f 88 [2] 21 88 [2] 1e 94 }

  condition:
    any of them
}