rule TTP_XOR_WriteProcessMemory_ee97 {
  strings:
    $key_ee97 = { b9 e5 [2] 8b c7 [2] 8d f2 [2] a3 f2 [2] 9c ee }

  condition:
    any of them
}