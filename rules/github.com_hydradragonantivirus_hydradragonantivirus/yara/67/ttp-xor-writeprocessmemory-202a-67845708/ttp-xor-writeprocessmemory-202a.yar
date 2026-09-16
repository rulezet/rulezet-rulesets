rule TTP_XOR_WriteProcessMemory_202a {
  strings:
    $key_202a = { 77 58 [2] 45 7a [2] 43 4f [2] 6d 4f [2] 52 53 }

  condition:
    any of them
}