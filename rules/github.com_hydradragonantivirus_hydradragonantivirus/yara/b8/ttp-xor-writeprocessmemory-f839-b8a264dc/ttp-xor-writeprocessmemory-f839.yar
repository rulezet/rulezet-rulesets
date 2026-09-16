rule TTP_XOR_WriteProcessMemory_f839 {
  strings:
    $key_f839 = { af 4b [2] 9d 69 [2] 9b 5c [2] b5 5c [2] 8a 40 }

  condition:
    any of them
}