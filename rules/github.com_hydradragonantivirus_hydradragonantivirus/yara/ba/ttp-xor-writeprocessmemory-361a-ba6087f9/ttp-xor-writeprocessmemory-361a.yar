rule TTP_XOR_WriteProcessMemory_361a {
  strings:
    $key_361a = { 61 68 [2] 53 4a [2] 55 7f [2] 7b 7f [2] 44 63 }

  condition:
    any of them
}