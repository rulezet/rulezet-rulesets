rule TTP_XOR_WriteProcessMemory_08ff {
  strings:
    $key_08ff = { 5f 8d [2] 6d af [2] 6b 9a [2] 45 9a [2] 7a 86 }

  condition:
    any of them
}