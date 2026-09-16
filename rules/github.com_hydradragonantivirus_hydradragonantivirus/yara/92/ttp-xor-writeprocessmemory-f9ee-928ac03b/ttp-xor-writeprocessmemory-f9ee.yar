rule TTP_XOR_WriteProcessMemory_f9ee {
  strings:
    $key_f9ee = { ae 9c [2] 9c be [2] 9a 8b [2] b4 8b [2] 8b 97 }

  condition:
    any of them
}