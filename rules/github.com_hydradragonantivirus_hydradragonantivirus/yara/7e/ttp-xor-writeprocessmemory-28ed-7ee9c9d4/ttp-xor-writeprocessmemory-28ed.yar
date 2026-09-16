rule TTP_XOR_WriteProcessMemory_28ed {
  strings:
    $key_28ed = { 7f 9f [2] 4d bd [2] 4b 88 [2] 65 88 [2] 5a 94 }

  condition:
    any of them
}