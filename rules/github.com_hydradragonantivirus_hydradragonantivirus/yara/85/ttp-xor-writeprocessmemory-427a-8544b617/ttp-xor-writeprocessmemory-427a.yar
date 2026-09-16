rule TTP_XOR_WriteProcessMemory_427a {
  strings:
    $key_427a = { 15 08 [2] 27 2a [2] 21 1f [2] 0f 1f [2] 30 03 }

  condition:
    any of them
}