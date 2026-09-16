rule TTP_XOR_WriteProcessMemory_1bc7 {
  strings:
    $key_1bc7 = { 4c b5 [2] 7e 97 [2] 78 a2 [2] 56 a2 [2] 69 be }

  condition:
    any of them
}