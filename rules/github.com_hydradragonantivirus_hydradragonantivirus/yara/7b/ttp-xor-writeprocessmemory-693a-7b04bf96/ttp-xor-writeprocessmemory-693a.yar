rule TTP_XOR_WriteProcessMemory_693a {
  strings:
    $key_693a = { 3e 48 [2] 0c 6a [2] 0a 5f [2] 24 5f [2] 1b 43 }

  condition:
    any of them
}