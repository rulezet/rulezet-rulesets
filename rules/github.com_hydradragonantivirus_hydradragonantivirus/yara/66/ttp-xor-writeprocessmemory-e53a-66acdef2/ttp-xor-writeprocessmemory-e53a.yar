rule TTP_XOR_WriteProcessMemory_e53a {
  strings:
    $key_e53a = { b2 48 [2] 80 6a [2] 86 5f [2] a8 5f [2] 97 43 }

  condition:
    any of them
}