rule TTP_XOR_WriteProcessMemory_621a {
  strings:
    $key_621a = { 35 68 [2] 07 4a [2] 01 7f [2] 2f 7f [2] 10 63 }

  condition:
    any of them
}