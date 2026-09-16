rule TTP_XOR_WriteProcessMemory_627a {
  strings:
    $key_627a = { 35 08 [2] 07 2a [2] 01 1f [2] 2f 1f [2] 10 03 }

  condition:
    any of them
}