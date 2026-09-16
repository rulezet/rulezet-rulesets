rule TTP_XOR_WriteProcessMemory_3bed {
  strings:
    $key_3bed = { 6c 9f [2] 5e bd [2] 58 88 [2] 76 88 [2] 49 94 }

  condition:
    any of them
}