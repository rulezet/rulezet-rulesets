rule TTP_XOR_WriteProcessMemory_2417 {
  strings:
    $key_2417 = { 73 65 [2] 41 47 [2] 47 72 [2] 69 72 [2] 56 6e }

  condition:
    any of them
}