rule TTP_XOR_WriteProcessMemory_d0ee {
  strings:
    $key_d0ee = { 87 9c [2] b5 be [2] b3 8b [2] 9d 8b [2] a2 97 }

  condition:
    any of them
}