rule TTP_XOR_WriteProcessMemory_766f {
  strings:
    $key_766f = { 21 1d [2] 13 3f [2] 15 0a [2] 3b 0a [2] 04 16 }

  condition:
    any of them
}