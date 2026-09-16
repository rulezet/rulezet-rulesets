rule TTP_XOR_WriteProcessMemory_046a {
  strings:
    $key_046a = { 53 18 [2] 61 3a [2] 67 0f [2] 49 0f [2] 76 13 }

  condition:
    any of them
}