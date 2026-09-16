rule TTP_XOR_WriteProcessMemory_2ded {
  strings:
    $key_2ded = { 7a 9f [2] 48 bd [2] 4e 88 [2] 60 88 [2] 5f 94 }

  condition:
    any of them
}