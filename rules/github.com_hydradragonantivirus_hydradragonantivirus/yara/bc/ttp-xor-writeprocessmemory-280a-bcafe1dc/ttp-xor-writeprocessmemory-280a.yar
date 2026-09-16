rule TTP_XOR_WriteProcessMemory_280a {
  strings:
    $key_280a = { 7f 78 [2] 4d 5a [2] 4b 6f [2] 65 6f [2] 5a 73 }

  condition:
    any of them
}