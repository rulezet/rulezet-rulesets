rule TTP_XOR_WriteProcessMemory_045a {
  strings:
    $key_045a = { 53 28 [2] 61 0a [2] 67 3f [2] 49 3f [2] 76 23 }

  condition:
    any of them
}