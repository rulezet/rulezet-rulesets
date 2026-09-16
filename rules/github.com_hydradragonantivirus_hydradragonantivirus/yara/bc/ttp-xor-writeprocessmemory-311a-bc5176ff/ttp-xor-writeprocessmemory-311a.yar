rule TTP_XOR_WriteProcessMemory_311a {
  strings:
    $key_311a = { 66 68 [2] 54 4a [2] 52 7f [2] 7c 7f [2] 43 63 }

  condition:
    any of them
}