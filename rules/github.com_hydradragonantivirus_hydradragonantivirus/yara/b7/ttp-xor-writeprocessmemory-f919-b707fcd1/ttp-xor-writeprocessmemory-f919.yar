rule TTP_XOR_WriteProcessMemory_f919 {
  strings:
    $key_f919 = { ae 6b [2] 9c 49 [2] 9a 7c [2] b4 7c [2] 8b 60 }

  condition:
    any of them
}