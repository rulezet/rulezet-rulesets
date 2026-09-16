rule TTP_XOR_WriteProcessMemory_2849 {
  strings:
    $key_2849 = { 7f 3b [2] 4d 19 [2] 4b 2c [2] 65 2c [2] 5a 30 }

  condition:
    any of them
}