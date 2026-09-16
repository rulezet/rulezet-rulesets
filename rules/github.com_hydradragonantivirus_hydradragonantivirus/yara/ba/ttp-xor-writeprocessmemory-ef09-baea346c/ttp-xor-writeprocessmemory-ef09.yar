rule TTP_XOR_WriteProcessMemory_ef09 {
  strings:
    $key_ef09 = { b8 7b [2] 8a 59 [2] 8c 6c [2] a2 6c [2] 9d 70 }

  condition:
    any of them
}