rule TTP_XOR_WriteProcessMemory_091a {
  strings:
    $key_091a = { 5e 68 [2] 6c 4a [2] 6a 7f [2] 44 7f [2] 7b 63 }

  condition:
    any of them
}