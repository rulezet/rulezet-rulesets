rule TTP_XOR_WriteProcessMemory_1fd7 {
  strings:
    $key_1fd7 = { 48 a5 [2] 7a 87 [2] 7c b2 [2] 52 b2 [2] 6d ae }

  condition:
    any of them
}