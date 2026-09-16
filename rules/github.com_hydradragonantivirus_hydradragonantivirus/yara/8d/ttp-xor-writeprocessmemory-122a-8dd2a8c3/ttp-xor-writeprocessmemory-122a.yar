rule TTP_XOR_WriteProcessMemory_122a {
  strings:
    $key_122a = { 45 58 [2] 77 7a [2] 71 4f [2] 5f 4f [2] 60 53 }

  condition:
    any of them
}