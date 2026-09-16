rule TTP_XOR_WriteProcessMemory_241a {
  strings:
    $key_241a = { 73 68 [2] 41 4a [2] 47 7f [2] 69 7f [2] 56 63 }

  condition:
    any of them
}