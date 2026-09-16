rule TTP_XOR_WriteProcessMemory_2dee {
  strings:
    $key_2dee = { 7a 9c [2] 48 be [2] 4e 8b [2] 60 8b [2] 5f 97 }

  condition:
    any of them
}