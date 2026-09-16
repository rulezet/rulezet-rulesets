rule TTP_XOR_WriteProcessMemory_c985 {
  strings:
    $key_c985 = { 9e f7 [2] ac d5 [2] aa e0 [2] 84 e0 [2] bb fc }

  condition:
    any of them
}