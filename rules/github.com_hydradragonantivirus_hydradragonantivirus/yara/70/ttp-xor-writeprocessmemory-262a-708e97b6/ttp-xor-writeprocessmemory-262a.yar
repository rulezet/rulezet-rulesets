rule TTP_XOR_WriteProcessMemory_262a {
  strings:
    $key_262a = { 71 58 [2] 43 7a [2] 45 4f [2] 6b 4f [2] 54 53 }

  condition:
    any of them
}