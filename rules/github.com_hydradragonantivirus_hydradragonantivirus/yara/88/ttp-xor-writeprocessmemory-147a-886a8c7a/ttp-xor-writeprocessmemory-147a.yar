rule TTP_XOR_WriteProcessMemory_147a {
  strings:
    $key_147a = { 43 08 [2] 71 2a [2] 77 1f [2] 59 1f [2] 66 03 }

  condition:
    any of them
}