rule TTP_XOR_WriteProcessMemory_5bed {
  strings:
    $key_5bed = { 0c 9f [2] 3e bd [2] 38 88 [2] 16 88 [2] 29 94 }

  condition:
    any of them
}