rule TTP_XOR_WriteProcessMemory_61ff {
  strings:
    $key_61ff = { 36 8d [2] 04 af [2] 02 9a [2] 2c 9a [2] 13 86 }

  condition:
    any of them
}