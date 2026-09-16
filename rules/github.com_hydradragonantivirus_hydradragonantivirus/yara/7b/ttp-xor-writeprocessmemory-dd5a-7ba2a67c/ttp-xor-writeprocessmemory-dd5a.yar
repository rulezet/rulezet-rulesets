rule TTP_XOR_WriteProcessMemory_dd5a {
  strings:
    $key_dd5a = { 8a 28 [2] b8 0a [2] be 3f [2] 90 3f [2] af 23 }

  condition:
    any of them
}