rule TTP_XOR_WriteProcessMemory_293a {
  strings:
    $key_293a = { 7e 48 [2] 4c 6a [2] 4a 5f [2] 64 5f [2] 5b 43 }

  condition:
    any of them
}