rule TTP_XOR_WriteProcessMemory_2875 {
  strings:
    $key_2875 = { 7f 07 [2] 4d 25 [2] 4b 10 [2] 65 10 [2] 5a 0c }

  condition:
    any of them
}