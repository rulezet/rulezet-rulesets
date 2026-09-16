rule TTP_XOR_WriteProcessMemory_565a {
  strings:
    $key_565a = { 01 28 [2] 33 0a [2] 35 3f [2] 1b 3f [2] 24 23 }

  condition:
    any of them
}