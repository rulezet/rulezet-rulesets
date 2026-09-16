rule TTP_XOR_WriteProcessMemory_7939 {
  strings:
    $key_7939 = { 2e 4b [2] 1c 69 [2] 1a 5c [2] 34 5c [2] 0b 40 }

  condition:
    any of them
}