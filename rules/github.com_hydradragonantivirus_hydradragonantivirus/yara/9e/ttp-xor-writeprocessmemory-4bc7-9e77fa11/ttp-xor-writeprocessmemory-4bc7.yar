rule TTP_XOR_WriteProcessMemory_4bc7 {
  strings:
    $key_4bc7 = { 1c b5 [2] 2e 97 [2] 28 a2 [2] 06 a2 [2] 39 be }

  condition:
    any of them
}