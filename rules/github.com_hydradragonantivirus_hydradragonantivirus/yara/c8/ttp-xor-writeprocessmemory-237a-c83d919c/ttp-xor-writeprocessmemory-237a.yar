rule TTP_XOR_WriteProcessMemory_237a {
  strings:
    $key_237a = { 74 08 [2] 46 2a [2] 40 1f [2] 6e 1f [2] 51 03 }

  condition:
    any of them
}