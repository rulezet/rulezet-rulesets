rule TTP_XOR_WriteProcessMemory_260a {
  strings:
    $key_260a = { 71 78 [2] 43 5a [2] 45 6f [2] 6b 6f [2] 54 73 }

  condition:
    any of them
}