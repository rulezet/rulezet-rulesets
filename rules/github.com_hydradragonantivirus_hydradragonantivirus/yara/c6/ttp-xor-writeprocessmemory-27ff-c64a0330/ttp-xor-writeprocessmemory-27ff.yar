rule TTP_XOR_WriteProcessMemory_27ff {
  strings:
    $key_27ff = { 70 8d [2] 42 af [2] 44 9a [2] 6a 9a [2] 55 86 }

  condition:
    any of them
}