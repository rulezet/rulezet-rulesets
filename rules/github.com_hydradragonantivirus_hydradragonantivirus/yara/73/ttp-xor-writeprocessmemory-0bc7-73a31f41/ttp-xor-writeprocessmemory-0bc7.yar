rule TTP_XOR_WriteProcessMemory_0bc7 {
  strings:
    $key_0bc7 = { 5c b5 [2] 6e 97 [2] 68 a2 [2] 46 a2 [2] 79 be }

  condition:
    any of them
}