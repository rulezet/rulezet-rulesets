rule TTP_XOR_WriteProcessMemory_315a {
  strings:
    $key_315a = { 66 28 [2] 54 0a [2] 52 3f [2] 7c 3f [2] 43 23 }

  condition:
    any of them
}