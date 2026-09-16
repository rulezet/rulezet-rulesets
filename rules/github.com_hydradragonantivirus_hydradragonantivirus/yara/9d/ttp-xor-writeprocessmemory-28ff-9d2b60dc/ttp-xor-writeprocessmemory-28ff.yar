rule TTP_XOR_WriteProcessMemory_28ff {
  strings:
    $key_28ff = { 7f 8d [2] 4d af [2] 4b 9a [2] 65 9a [2] 5a 86 }

  condition:
    any of them
}