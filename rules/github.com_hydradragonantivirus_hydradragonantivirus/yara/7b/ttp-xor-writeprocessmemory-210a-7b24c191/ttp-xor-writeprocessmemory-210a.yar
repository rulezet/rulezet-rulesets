rule TTP_XOR_WriteProcessMemory_210a {
  strings:
    $key_210a = { 76 78 [2] 44 5a [2] 42 6f [2] 6c 6f [2] 53 73 }

  condition:
    any of them
}