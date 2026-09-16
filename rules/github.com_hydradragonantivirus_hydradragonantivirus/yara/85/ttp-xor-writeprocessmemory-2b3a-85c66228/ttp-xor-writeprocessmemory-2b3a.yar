rule TTP_XOR_WriteProcessMemory_2b3a {
  strings:
    $key_2b3a = { 7c 48 [2] 4e 6a [2] 48 5f [2] 66 5f [2] 59 43 }

  condition:
    any of them
}