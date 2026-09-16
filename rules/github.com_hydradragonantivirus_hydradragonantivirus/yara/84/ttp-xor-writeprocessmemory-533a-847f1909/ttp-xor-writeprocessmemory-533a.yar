rule TTP_XOR_WriteProcessMemory_533a {
  strings:
    $key_533a = { 04 48 [2] 36 6a [2] 30 5f [2] 1e 5f [2] 21 43 }

  condition:
    any of them
}