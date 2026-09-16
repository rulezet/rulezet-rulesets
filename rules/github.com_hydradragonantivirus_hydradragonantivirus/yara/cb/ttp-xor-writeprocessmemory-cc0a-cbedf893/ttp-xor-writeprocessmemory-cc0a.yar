rule TTP_XOR_WriteProcessMemory_cc0a {
  strings:
    $key_cc0a = { 9b 78 [2] a9 5a [2] af 6f [2] 81 6f [2] be 73 }

  condition:
    any of them
}