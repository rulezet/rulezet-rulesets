rule TTP_XOR_WriteProcessMemory_04ff {
  strings:
    $key_04ff = { 53 8d [2] 61 af [2] 67 9a [2] 49 9a [2] 76 86 }

  condition:
    any of them
}