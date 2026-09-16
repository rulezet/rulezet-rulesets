rule TTP_XOR_WriteProcessMemory_22ff {
  strings:
    $key_22ff = { 75 8d [2] 47 af [2] 41 9a [2] 6f 9a [2] 50 86 }

  condition:
    any of them
}