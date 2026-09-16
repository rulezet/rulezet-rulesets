rule TTP_XOR_WriteProcessMemory_203a {
  strings:
    $key_203a = { 77 48 [2] 45 6a [2] 43 5f [2] 6d 5f [2] 52 43 }

  condition:
    any of them
}