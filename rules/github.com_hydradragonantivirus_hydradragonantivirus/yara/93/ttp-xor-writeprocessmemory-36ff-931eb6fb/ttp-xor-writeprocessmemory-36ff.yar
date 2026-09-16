rule TTP_XOR_WriteProcessMemory_36ff {
  strings:
    $key_36ff = { 61 8d [2] 53 af [2] 55 9a [2] 7b 9a [2] 44 86 }

  condition:
    any of them
}