rule TTP_XOR_WriteProcessMemory_38ed {
  strings:
    $key_38ed = { 6f 9f [2] 5d bd [2] 5b 88 [2] 75 88 [2] 4a 94 }

  condition:
    any of them
}