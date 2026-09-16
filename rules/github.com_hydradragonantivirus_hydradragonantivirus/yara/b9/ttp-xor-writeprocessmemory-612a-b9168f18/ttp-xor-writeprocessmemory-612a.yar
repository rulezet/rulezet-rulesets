rule TTP_XOR_WriteProcessMemory_612a {
  strings:
    $key_612a = { 36 58 [2] 04 7a [2] 02 4f [2] 2c 4f [2] 13 53 }

  condition:
    any of them
}