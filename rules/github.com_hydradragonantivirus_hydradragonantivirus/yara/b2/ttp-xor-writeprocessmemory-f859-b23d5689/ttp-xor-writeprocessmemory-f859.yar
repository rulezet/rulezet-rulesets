rule TTP_XOR_WriteProcessMemory_f859 {
  strings:
    $key_f859 = { af 2b [2] 9d 09 [2] 9b 3c [2] b5 3c [2] 8a 20 }

  condition:
    any of them
}