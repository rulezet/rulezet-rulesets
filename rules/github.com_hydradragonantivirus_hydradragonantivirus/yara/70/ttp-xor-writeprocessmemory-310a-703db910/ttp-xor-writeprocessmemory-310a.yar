rule TTP_XOR_WriteProcessMemory_310a {
  strings:
    $key_310a = { 66 78 [2] 54 5a [2] 52 6f [2] 7c 6f [2] 43 73 }

  condition:
    any of them
}