rule TTP_XOR_WriteProcessMemory_510a {
  strings:
    $key_510a = { 06 78 [2] 34 5a [2] 32 6f [2] 1c 6f [2] 23 73 }

  condition:
    any of them
}