rule TTP_XOR_WriteProcessMemory_223a {
  strings:
    $key_223a = { 75 48 [2] 47 6a [2] 41 5f [2] 6f 5f [2] 50 43 }

  condition:
    any of them
}