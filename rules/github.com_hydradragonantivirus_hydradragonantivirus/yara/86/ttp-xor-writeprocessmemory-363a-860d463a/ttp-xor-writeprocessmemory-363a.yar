rule TTP_XOR_WriteProcessMemory_363a {
  strings:
    $key_363a = { 61 48 [2] 53 6a [2] 55 5f [2] 7b 5f [2] 44 43 }

  condition:
    any of them
}