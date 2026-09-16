rule TTP_XOR_WriteProcessMemory_fbed {
  strings:
    $key_fbed = { ac 9f [2] 9e bd [2] 98 88 [2] b6 88 [2] 89 94 }

  condition:
    any of them
}