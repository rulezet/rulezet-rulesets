rule TTP_XOR_WriteProcessMemory_767a {
  strings:
    $key_767a = { 21 08 [2] 13 2a [2] 15 1f [2] 3b 1f [2] 04 03 }

  condition:
    any of them
}