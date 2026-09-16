rule TTP_XOR_WriteProcessMemory_041a {
  strings:
    $key_041a = { 53 68 [2] 61 4a [2] 67 7f [2] 49 7f [2] 76 63 }

  condition:
    any of them
}