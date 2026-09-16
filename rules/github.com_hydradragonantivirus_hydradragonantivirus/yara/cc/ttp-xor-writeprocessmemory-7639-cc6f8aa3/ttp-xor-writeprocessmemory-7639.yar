rule TTP_XOR_WriteProcessMemory_7639 {
  strings:
    $key_7639 = { 21 4b [2] 13 69 [2] 15 5c [2] 3b 5c [2] 04 40 }

  condition:
    any of them
}