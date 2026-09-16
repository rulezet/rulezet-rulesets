rule TTP_XOR_WriteProcessMemory_f8ed {
  strings:
    $key_f8ed = { af 9f [2] 9d bd [2] 9b 88 [2] b5 88 [2] 8a 94 }

  condition:
    any of them
}