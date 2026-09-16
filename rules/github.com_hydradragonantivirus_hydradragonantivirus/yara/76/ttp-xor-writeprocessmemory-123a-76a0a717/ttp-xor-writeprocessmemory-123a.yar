rule TTP_XOR_WriteProcessMemory_123a {
  strings:
    $key_123a = { 45 48 [2] 77 6a [2] 71 5f [2] 5f 5f [2] 60 43 }

  condition:
    any of them
}