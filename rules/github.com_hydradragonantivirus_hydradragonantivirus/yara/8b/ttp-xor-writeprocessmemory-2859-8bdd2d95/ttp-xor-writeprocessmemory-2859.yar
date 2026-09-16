rule TTP_XOR_WriteProcessMemory_2859 {
  strings:
    $key_2859 = { 7f 2b [2] 4d 09 [2] 4b 3c [2] 65 3c [2] 5a 20 }

  condition:
    any of them
}