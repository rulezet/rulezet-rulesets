rule TTP_XOR_WriteProcessMemory_c83a {
  strings:
    $key_c83a = { 9f 48 [2] ad 6a [2] ab 5f [2] 85 5f [2] ba 43 }

  condition:
    any of them
}