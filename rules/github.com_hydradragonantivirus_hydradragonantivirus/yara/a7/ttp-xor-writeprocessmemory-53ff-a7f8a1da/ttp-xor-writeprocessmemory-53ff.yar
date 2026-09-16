rule TTP_XOR_WriteProcessMemory_53ff {
  strings:
    $key_53ff = { 04 8d [2] 36 af [2] 30 9a [2] 1e 9a [2] 21 86 }

  condition:
    any of them
}