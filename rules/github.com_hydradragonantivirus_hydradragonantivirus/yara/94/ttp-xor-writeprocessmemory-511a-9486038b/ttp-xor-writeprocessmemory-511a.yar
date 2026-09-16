rule TTP_XOR_WriteProcessMemory_511a {
  strings:
    $key_511a = { 06 68 [2] 34 4a [2] 32 7f [2] 1c 7f [2] 23 63 }

  condition:
    any of them
}