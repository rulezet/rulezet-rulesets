rule TTP_XOR_WriteProcessMemory_eec7 {
  strings:
    $key_eec7 = { b9 b5 [2] 8b 97 [2] 8d a2 [2] a3 a2 [2] 9c be }

  condition:
    any of them
}