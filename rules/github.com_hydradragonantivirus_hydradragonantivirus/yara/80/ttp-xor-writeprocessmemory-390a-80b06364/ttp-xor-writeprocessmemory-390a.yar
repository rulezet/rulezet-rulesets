rule TTP_XOR_WriteProcessMemory_390a {
  strings:
    $key_390a = { 6e 78 [2] 5c 5a [2] 5a 6f [2] 74 6f [2] 4b 73 }

  condition:
    any of them
}