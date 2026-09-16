rule TTP_XOR_WriteProcessMemory_021a {
  strings:
    $key_021a = { 55 68 [2] 67 4a [2] 61 7f [2] 4f 7f [2] 70 63 }

  condition:
    any of them
}