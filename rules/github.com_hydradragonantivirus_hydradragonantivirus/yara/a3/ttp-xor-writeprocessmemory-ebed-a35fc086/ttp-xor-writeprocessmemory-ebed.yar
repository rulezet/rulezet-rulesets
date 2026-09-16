rule TTP_XOR_WriteProcessMemory_ebed {
  strings:
    $key_ebed = { bc 9f [2] 8e bd [2] 88 88 [2] a6 88 [2] 99 94 }

  condition:
    any of them
}