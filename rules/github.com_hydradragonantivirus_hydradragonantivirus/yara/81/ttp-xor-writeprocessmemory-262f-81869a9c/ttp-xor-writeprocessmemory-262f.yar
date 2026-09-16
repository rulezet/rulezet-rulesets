rule TTP_XOR_WriteProcessMemory_262f {
  strings:
    $key_262f = { 71 5d [2] 43 7f [2] 45 4a [2] 6b 4a [2] 54 56 }

  condition:
    any of them
}