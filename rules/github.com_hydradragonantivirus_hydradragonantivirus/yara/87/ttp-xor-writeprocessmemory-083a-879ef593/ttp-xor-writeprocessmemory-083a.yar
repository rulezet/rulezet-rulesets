rule TTP_XOR_WriteProcessMemory_083a {
  strings:
    $key_083a = { 5f 48 [2] 6d 6a [2] 6b 5f [2] 45 5f [2] 7a 43 }

  condition:
    any of them
}