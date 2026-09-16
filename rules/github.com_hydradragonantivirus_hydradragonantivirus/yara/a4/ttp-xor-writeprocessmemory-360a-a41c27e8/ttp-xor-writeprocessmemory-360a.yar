rule TTP_XOR_WriteProcessMemory_360a {
  strings:
    $key_360a = { 61 78 [2] 53 5a [2] 55 6f [2] 7b 6f [2] 44 73 }

  condition:
    any of them
}