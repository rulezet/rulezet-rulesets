rule TTP_XOR_WriteProcessMemory_267a {
  strings:
    $key_267a = { 71 08 [2] 43 2a [2] 45 1f [2] 6b 1f [2] 54 03 }

  condition:
    any of them
}