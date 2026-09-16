rule TTP_XOR_WriteProcessMemory_0bed {
  strings:
    $key_0bed = { 5c 9f [2] 6e bd [2] 68 88 [2] 46 88 [2] 79 94 }

  condition:
    any of them
}