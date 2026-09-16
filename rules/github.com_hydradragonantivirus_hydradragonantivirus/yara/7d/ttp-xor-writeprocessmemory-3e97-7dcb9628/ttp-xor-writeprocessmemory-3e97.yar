rule TTP_XOR_WriteProcessMemory_3e97 {
  strings:
    $key_3e97 = { 69 e5 [2] 5b c7 [2] 5d f2 [2] 73 f2 [2] 4c ee }

  condition:
    any of them
}