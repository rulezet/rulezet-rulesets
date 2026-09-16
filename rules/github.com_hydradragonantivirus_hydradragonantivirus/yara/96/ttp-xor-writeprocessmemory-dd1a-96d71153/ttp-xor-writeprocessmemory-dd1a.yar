rule TTP_XOR_WriteProcessMemory_dd1a {
  strings:
    $key_dd1a = { 8a 68 [2] b8 4a [2] be 7f [2] 90 7f [2] af 63 }

  condition:
    any of them
}