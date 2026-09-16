rule TTP_XOR_WriteProcessMemory_423a {
  strings:
    $key_423a = { 15 48 [2] 27 6a [2] 21 5f [2] 0f 5f [2] 30 43 }

  condition:
    any of them
}