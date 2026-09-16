rule TTP_XOR_WriteProcessMemory_adee {
  strings:
    $key_adee = { fa 9c [2] c8 be [2] ce 8b [2] e0 8b [2] df 97 }

  condition:
    any of them
}