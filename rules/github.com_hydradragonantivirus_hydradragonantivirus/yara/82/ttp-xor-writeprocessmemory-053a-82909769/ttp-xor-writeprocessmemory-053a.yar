rule TTP_XOR_WriteProcessMemory_053a {
  strings:
    $key_053a = { 52 48 [2] 60 6a [2] 66 5f [2] 48 5f [2] 77 43 }

  condition:
    any of them
}