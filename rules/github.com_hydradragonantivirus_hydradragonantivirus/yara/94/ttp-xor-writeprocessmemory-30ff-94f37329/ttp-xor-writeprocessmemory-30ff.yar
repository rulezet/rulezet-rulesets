rule TTP_XOR_WriteProcessMemory_30ff {
  strings:
    $key_30ff = { 67 8d [2] 55 af [2] 53 9a [2] 7d 9a [2] 42 86 }

  condition:
    any of them
}