rule TTP_XOR_WriteProcessMemory_fa45 {
  strings:
    $key_fa45 = { ad 37 [2] 9f 15 [2] 99 20 [2] b7 20 [2] 88 3c }

  condition:
    any of them
}