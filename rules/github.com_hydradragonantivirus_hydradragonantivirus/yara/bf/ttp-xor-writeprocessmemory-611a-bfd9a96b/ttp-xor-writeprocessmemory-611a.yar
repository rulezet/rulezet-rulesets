rule TTP_XOR_WriteProcessMemory_611a {
  strings:
    $key_611a = { 36 68 [2] 04 4a [2] 02 7f [2] 2c 7f [2] 13 63 }

  condition:
    any of them
}