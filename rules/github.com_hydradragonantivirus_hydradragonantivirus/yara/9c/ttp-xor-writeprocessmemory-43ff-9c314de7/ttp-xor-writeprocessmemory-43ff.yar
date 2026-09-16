rule TTP_XOR_WriteProcessMemory_43ff {
  strings:
    $key_43ff = { 14 8d [2] 26 af [2] 20 9a [2] 0e 9a [2] 31 86 }

  condition:
    any of them
}