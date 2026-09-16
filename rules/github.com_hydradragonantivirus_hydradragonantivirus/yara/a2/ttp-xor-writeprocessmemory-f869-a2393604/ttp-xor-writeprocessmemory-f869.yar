rule TTP_XOR_WriteProcessMemory_f869 {
  strings:
    $key_f869 = { af 1b [2] 9d 39 [2] 9b 0c [2] b5 0c [2] 8a 10 }

  condition:
    any of them
}