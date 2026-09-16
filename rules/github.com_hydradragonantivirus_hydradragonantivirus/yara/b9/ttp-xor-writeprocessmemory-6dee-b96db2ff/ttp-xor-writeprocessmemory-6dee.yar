rule TTP_XOR_WriteProcessMemory_6dee {
  strings:
    $key_6dee = { 3a 9c [2] 08 be [2] 0e 8b [2] 20 8b [2] 1f 97 }

  condition:
    any of them
}