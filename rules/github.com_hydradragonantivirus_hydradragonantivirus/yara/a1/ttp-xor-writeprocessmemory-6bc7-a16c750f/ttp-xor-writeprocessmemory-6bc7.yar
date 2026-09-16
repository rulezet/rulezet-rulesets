rule TTP_XOR_WriteProcessMemory_6bc7 {
  strings:
    $key_6bc7 = { 3c b5 [2] 0e 97 [2] 08 a2 [2] 26 a2 [2] 19 be }

  condition:
    any of them
}