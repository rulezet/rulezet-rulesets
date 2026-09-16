rule TTP_XOR_WriteProcessMemory_4bed {
  strings:
    $key_4bed = { 1c 9f [2] 2e bd [2] 28 88 [2] 06 88 [2] 39 94 }

  condition:
    any of them
}