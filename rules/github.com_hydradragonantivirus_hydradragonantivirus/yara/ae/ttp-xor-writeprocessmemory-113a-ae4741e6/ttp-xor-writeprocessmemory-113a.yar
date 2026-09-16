rule TTP_XOR_WriteProcessMemory_113a {
  strings:
    $key_113a = { 46 48 [2] 74 6a [2] 72 5f [2] 5c 5f [2] 63 43 }

  condition:
    any of them
}