rule TTP_XOR_WriteProcessMemory_0ded {
  strings:
    $key_0ded = { 5a 9f [2] 68 bd [2] 6e 88 [2] 40 88 [2] 7f 94 }

  condition:
    any of them
}