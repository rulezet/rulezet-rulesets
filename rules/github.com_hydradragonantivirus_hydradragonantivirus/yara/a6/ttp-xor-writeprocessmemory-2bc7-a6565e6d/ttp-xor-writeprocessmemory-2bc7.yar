rule TTP_XOR_WriteProcessMemory_2bc7 {
  strings:
    $key_2bc7 = { 7c b5 [2] 4e 97 [2] 48 a2 [2] 66 a2 [2] 59 be }

  condition:
    any of them
}