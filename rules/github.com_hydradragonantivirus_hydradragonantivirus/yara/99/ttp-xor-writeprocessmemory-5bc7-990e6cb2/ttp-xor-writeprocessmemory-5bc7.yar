rule TTP_XOR_WriteProcessMemory_5bc7 {
  strings:
    $key_5bc7 = { 0c b5 [2] 3e 97 [2] 38 a2 [2] 16 a2 [2] 29 be }

  condition:
    any of them
}