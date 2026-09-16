rule TTP_XOR_WriteProcessMemory_f8ee {
  strings:
    $key_f8ee = { af 9c [2] 9d be [2] 9b 8b [2] b5 8b [2] 8a 97 }

  condition:
    any of them
}