rule TTP_XOR_WriteProcessMemory_2439 {
  strings:
    $key_2439 = { 73 4b [2] 41 69 [2] 47 5c [2] 69 5c [2] 56 40 }

  condition:
    any of them
}