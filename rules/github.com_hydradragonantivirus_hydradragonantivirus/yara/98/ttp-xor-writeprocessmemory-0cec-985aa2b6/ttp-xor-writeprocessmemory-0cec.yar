rule TTP_XOR_WriteProcessMemory_0cec {
  strings:
    $key_0cec = { 5b 9e [2] 69 bc [2] 6f 89 [2] 41 89 [2] 7e 95 }

  condition:
    any of them
}