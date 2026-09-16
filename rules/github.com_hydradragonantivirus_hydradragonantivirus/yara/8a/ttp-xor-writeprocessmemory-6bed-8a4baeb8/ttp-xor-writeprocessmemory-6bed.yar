rule TTP_XOR_WriteProcessMemory_6bed {
  strings:
    $key_6bed = { 3c 9f [2] 0e bd [2] 08 88 [2] 26 88 [2] 19 94 }

  condition:
    any of them
}