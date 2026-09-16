rule TTP_XOR_WriteProcessMemory_260f {
  strings:
    $key_260f = { 71 7d [2] 43 5f [2] 45 6a [2] 6b 6a [2] 54 76 }

  condition:
    any of them
}