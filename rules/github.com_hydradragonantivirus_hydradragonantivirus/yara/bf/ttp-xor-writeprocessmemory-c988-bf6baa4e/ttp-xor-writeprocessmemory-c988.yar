rule TTP_XOR_WriteProcessMemory_c988 {
  strings:
    $key_c988 = { 9e fa [2] ac d8 [2] aa ed [2] 84 ed [2] bb f1 }

  condition:
    any of them
}