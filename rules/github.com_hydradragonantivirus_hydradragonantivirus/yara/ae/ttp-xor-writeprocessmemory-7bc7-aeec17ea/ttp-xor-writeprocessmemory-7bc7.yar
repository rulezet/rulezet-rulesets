rule TTP_XOR_WriteProcessMemory_7bc7 {
  strings:
    $key_7bc7 = { 2c b5 [2] 1e 97 [2] 18 a2 [2] 36 a2 [2] 09 be }

  condition:
    any of them
}