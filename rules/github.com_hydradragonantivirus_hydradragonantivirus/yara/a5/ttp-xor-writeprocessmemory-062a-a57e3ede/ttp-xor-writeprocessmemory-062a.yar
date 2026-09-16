rule TTP_XOR_WriteProcessMemory_062a {
  strings:
    $key_062a = { 51 58 [2] 63 7a [2] 65 4f [2] 4b 4f [2] 74 53 }

  condition:
    any of them
}