rule TTP_XOR_WriteProcessMemory_6ded {
  strings:
    $key_6ded = { 3a 9f [2] 08 bd [2] 0e 88 [2] 20 88 [2] 1f 94 }

  condition:
    any of them
}