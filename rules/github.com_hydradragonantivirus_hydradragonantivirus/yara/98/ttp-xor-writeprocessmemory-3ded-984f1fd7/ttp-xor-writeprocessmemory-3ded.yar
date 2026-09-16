rule TTP_XOR_WriteProcessMemory_3ded {
  strings:
    $key_3ded = { 6a 9f [2] 58 bd [2] 5e 88 [2] 70 88 [2] 4f 94 }

  condition:
    any of them
}