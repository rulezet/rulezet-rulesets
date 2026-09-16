rule TTP_XOR_WriteProcessMemory_061a {
  strings:
    $key_061a = { 51 68 [2] 63 4a [2] 65 7f [2] 4b 7f [2] 74 63 }

  condition:
    any of them
}