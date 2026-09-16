rule TTP_XOR_WriteProcessMemory_383a {
  strings:
    $key_383a = { 6f 48 [2] 5d 6a [2] 5b 5f [2] 75 5f [2] 4a 43 }

  condition:
    any of them
}