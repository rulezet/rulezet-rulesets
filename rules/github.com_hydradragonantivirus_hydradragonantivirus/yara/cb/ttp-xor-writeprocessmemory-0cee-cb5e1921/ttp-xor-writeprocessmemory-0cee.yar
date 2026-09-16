rule TTP_XOR_WriteProcessMemory_0cee {
  strings:
    $key_0cee = { 5b 9c [2] 69 be [2] 6f 8b [2] 41 8b [2] 7e 97 }

  condition:
    any of them
}